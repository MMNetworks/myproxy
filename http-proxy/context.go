package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"myproxy/logging"
	"myproxy/protocol"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"os"
)
type accessLog struct {
	// Pointer of access log record struct handled this Session.
	StartRecord logging.AccessLogRecord
	EndRecord logging.AccessLogRecord
}

// Context keeps context of each proxy request.
type Context struct {
	// Pointer of Proxy struct handled this context.
	// It's using internally. Don't change in Context struct!
	Prx *Proxy

	// Session number of this context obtained from Proxy struct.
	SessionNo int64

	// Sub session number of processing remote connection.
	SubSessionNo int64

	// Original Proxy request.
	// It's using internally. Don't change in Context struct!
	Req *http.Request

	// Original Proxy request, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectReq *http.Request

	// Action of after the CONNECT, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectAction ConnectAction

	// Remote host, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectHost string

	// Upstream Proxy host
	// It's using internally. Don't change in Context struct!
	UpstreamProxy string

	// Upstream Proxy host
	// It's using internally. Don't change in Context struct!
	AccessLog accessLog

	// User data to use free.
	UserData interface{}

	hijTLSConn   *tls.Conn
	hijTLSReader *bufio.Reader
}

func (ctx *Context) onAccept(w http.ResponseWriter, r *http.Request) bool {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Accept", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnAccept(ctx, w, r)
}

func (ctx *Context) onAuth(authType string, user string, pass string) bool {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Auth", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnAuth(ctx, authType, user, pass)
}

func (ctx *Context) onConnect(host string) (ConnectAction ConnectAction,
	newHost string) {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Connect", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnConnect(ctx, host)
}

func (ctx *Context) onRequest(req *http.Request) (resp *http.Response) {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Request", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnRequest(ctx, req)
}

func (ctx *Context) onResponse(req *http.Request, resp *http.Response) {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Response", ErrPanic, err)
		}
	}()
	ctx.Prx.OnResponse(ctx, req, resp)
}

func (ctx *Context) doError(where string, err *Error, opErr error) {
	if ctx.Prx.OnError == nil {
		return
	}
	ctx.Prx.OnError(ctx, where, err, opErr)
}

func (ctx *Context) doAccept(w http.ResponseWriter, r *http.Request) bool {
	ctx.Req = r
	if !r.ProtoAtLeast(1, 0) || r.ProtoAtLeast(2, 0) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Accept", ErrNotSupportHTTPVer, nil)
		return true
	}
	if ctx.Prx.OnAccept != nil && ctx.onAccept(w, r) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		return true
	}
	return false
}

func (ctx *Context) doAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "CONNECT" && !r.URL.IsAbs() {
		return false
	}
	if ctx.Prx.OnAuth == nil {
		return false
	}
	prxAuthType := ctx.Prx.AuthType
	if prxAuthType == "" {
		prxAuthType = "Basic"
	}
	unauthorized := false
	authParts := strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)
	if len(authParts) >= 2 {
		authType := authParts[0]
		authData := authParts[1]
		if prxAuthType == authType {
			unauthorized = true
			switch authType {
			case "Basic":
				userpassraw, err := base64.StdEncoding.DecodeString(authData)
				if err == nil {
					userpass := strings.SplitN(string(userpassraw), ":", 2)
					if len(userpass) >= 2 && ctx.onAuth(authType, userpass[0], userpass[1]) {
						return false
					}
				}
			default:
				unauthorized = false
			}
		}
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	respCode := 407
	respBody := "Proxy Authentication Required"
	if unauthorized {
		respBody += " [Unauthorized]"
	}
	err := ServeInMemory(w, respCode, map[string][]string{"Proxy-Authenticate": {prxAuthType}},
		[]byte(respBody))
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Auth", ErrResponseWrite, err)
	}
	return true
}

func (ctx *Context) doConnect(w http.ResponseWriter, r *http.Request) (b bool) {
	b = true
	if r.Method != "CONNECT" {
		b = false
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Connect", ErrNotSupportHijacking, nil)
		return
	}
	conn, _, err := hij.Hijack()
	if err != nil {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Connect", ErrNotSupportHijacking, err)
		return
	}
	hijConn := conn
	ctx.ConnectReq = r
	ctx.ConnectAction = ConnectProxy
	host := r.URL.Host
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	if ctx.Prx.OnConnect != nil {
		var newHost string
		ctx.ConnectAction, newHost = ctx.onConnect(host)
		if newHost != "" {
			host = newHost
		}
	}
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	ctx.ConnectHost = host
	switch ctx.ConnectAction {
	case ConnectProxy:
		conn, err := ctx.Prx.Dial(ctx, "tcp", host)
		if err != nil {
			hijConn.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
			hijConn.Close()
			ctx.doError("Connect", ErrRemoteConnect, err)
			return
		}
		remoteConn := conn.(*net.TCPConn)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			remoteConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrResponseWrite, err)
			}
			return
		}
		logging.Printf("DEBUG", "doConnect: New Connection to %s Session ID: %d\n",host,ctx.SessionNo)
		ctx.AccessLog.StartRecord.Proxy, err = os.Hostname()
		ctx.AccessLog.StartRecord.SessionID = ctx.SessionNo
		ctx.AccessLog.StartRecord.State = "start"
		ctx.AccessLog.StartRecord.SourceIP = hijConn.RemoteAddr().String()
		ctx.AccessLog.StartRecord.DestinationIP = remoteConn.RemoteAddr().String()

		if len(ctx.ConnectReq.Header.Values("X-Forwarded-For")) > 0 {
			forwardedValues := ctx.ConnectReq.Header.Values("X-Forwarded-For")
			ctx.AccessLog.StartRecord.ForwardedIP = strings.Join(forwardedValues[:],",")
		} else if len(ctx.ConnectReq.Header.Values("Forwarded")) > 0 {
			forwardedValues := ctx.ConnectReq.Header.Values("Forwarded")
			ctx.AccessLog.StartRecord.ForwardedIP = strings.Join(forwardedValues[:],",")
                } else {
			ctx.AccessLog.StartRecord.ForwardedIP = ""
		}
		ctx.AccessLog.StartRecord.Method = "CONNECT"
		ctx.AccessLog.StartRecord.Scheme = ctx.ConnectReq.URL.Scheme
		ctx.AccessLog.StartRecord.Url = ctx.ConnectReq.URL.String()
		ctx.AccessLog.StartRecord.Version = ctx.ConnectReq.Proto
		ctx.AccessLog.StartRecord.Status = ""
		ctx.AccessLog.StartRecord.BytesIN = 0
		ctx.AccessLog.StartRecord.BytesOUT = 0
		ctx.AccessLog.StartRecord.Protocol = ""
		ctx.AccessLog.StartRecord.Starttime = time.Now()
		ctx.AccessLog.StartRecord.Endtime = time.Now()
		ctx.AccessLog.StartRecord.Duration = time.Duration(0)
		ctx.AccessLog.EndRecord = ctx.AccessLog.StartRecord
        	ctx.AccessLog.EndRecord.State = "end"
		logging.AccesslogWrite(ctx.AccessLog.StartRecord)
		var FirstPacket bool = true
		var FirstPacketResponse bool = true
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer func() {
				e := recover()
				err, ok := e.(error)
				if !ok {
					return
				}
				hijConn.Close()
				remoteConn.Close()
				if !isConnectionClosed(err) {
					ctx.doError("Connect", ErrRequestRead, err)
				} // else {
                			// logging.Printf("DEBUG", "doConnect: Connection closed. Session ID: %d\n",ctx.SessionNo)
				// }
			}()
			//
			// Analyse first packet for protocol idenification and SNI compliance
			//
			buf := make([]byte, 65535)
			if FirstPacket {
				n, err := hijConn.Read(buf)
				if err != nil && err != io.EOF {
					panic(err)
				}
				if n != 0 {
					_, err = remoteConn.Write(buf[:n])
					if err != nil {
						panic(err)
					}
					protocol, description :=  protocol.AnalyseFirstPacket(buf[:n])
					if protocol != "Unknown" {
						if protocol != "TLS" {
							logging.Printf("INFO", "doConnect: Found tunnelled protocol in request: %s %s\n",protocol,description)
						} else {
							logging.Printf("INFO", "doConnect: Found in request: %s %s\n",protocol,description)
						}
						ctx.AccessLog.EndRecord.Protocol = protocol
					}
				}
				FirstPacket = false
				ctx.AccessLog.EndRecord.BytesOUT = ctx.AccessLog.EndRecord.BytesOUT + int64(n)
			} 
			n, err := io.Copy(remoteConn, hijConn)
			ctx.AccessLog.EndRecord.BytesOUT = ctx.AccessLog.EndRecord.BytesOUT + n
			if err != nil {
				panic(err)
			}
			remoteConn.CloseWrite()
			if c, ok := hijConn.(*net.TCPConn); ok {
				c.CloseRead()
			}
                	// logging.Printf("DEBUG", "doConnect: Connection closed. Session ID: %d\n",ctx.SessionNo)
		}()
		go func() {
			defer wg.Done()
			defer func() {
				e := recover()
				err, ok := e.(error)
				if !ok {
					return
				}
				hijConn.Close()
				remoteConn.Close()
				if !isConnectionClosed(err) {
					ctx.doError("Connect", ErrResponseWrite, err)
				} else {
                			logging.Printf("DEBUG", "doConnect: Connection closed. Session ID: %d\n",ctx.SessionNo)
					ctx.AccessLog.EndRecord.Endtime = time.Now()
					ctx.AccessLog.EndRecord.Duration = ctx.AccessLog.EndRecord.Endtime.Sub(ctx.AccessLog.EndRecord.Starttime)
					logging.AccesslogWrite(ctx.AccessLog.EndRecord)
				}
			}()
			//
			// Analyse first response packet for protocol idenification and SNI compliance
			//
			buf := make([]byte, 65535)
			if FirstPacketResponse {
				n, err := remoteConn.Read(buf)
				if err != nil && err != io.EOF {
					panic(err)
				}
				if n != 0 {
					_, err = hijConn.Write(buf[:n])
					if err != nil {
						panic(err)
					}
					protocol, description :=  protocol.AnalyseFirstPacketResponse(buf[:n])
					if protocol != "Unknown" {
						logging.Printf("INFO", "doConnect: Found tunnelled protocol in response: %s %s\n",protocol,description)
						ctx.AccessLog.EndRecord.Protocol = protocol
					}
				}
				FirstPacketResponse = false
				ctx.AccessLog.EndRecord.BytesIN = ctx.AccessLog.EndRecord.BytesIN + int64(n)
			} 
			n, err := io.Copy(hijConn, remoteConn)
			ctx.AccessLog.EndRecord.BytesIN = ctx.AccessLog.EndRecord.BytesIN + n
			if err != nil {
				panic(err)
			}
			remoteConn.CloseRead()
			if c, ok := hijConn.(*net.TCPConn); ok {
				c.CloseWrite()
			}
                	logging.Printf("DEBUG", "doConnect: Connection closed. Session ID: %d\n",ctx.SessionNo)
			ctx.AccessLog.EndRecord.Endtime = time.Now()
			ctx.AccessLog.EndRecord.Duration = ctx.AccessLog.EndRecord.Endtime.Sub(ctx.AccessLog.EndRecord.Starttime)
			logging.AccesslogWrite(ctx.AccessLog.EndRecord)
		}()
		wg.Wait()
		hijConn.Close()
		remoteConn.Close()
	case ConnectMitm:
		tlsConfig := &tls.Config{}
		cert := ctx.Prx.signer.SignHost(host)
		if cert == nil {
			hijConn.Close()
			ctx.doError("Connect", ErrTLSSignHost, err)
			return
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, *cert)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrResponseWrite, err)
			}
			return
		}
		ctx.hijTLSConn = tls.Server(hijConn, tlsConfig)
		if err := ctx.hijTLSConn.Handshake(); err != nil {
			ctx.hijTLSConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrTLSHandshake, err)
			}
			return
		}
		ctx.hijTLSReader = bufio.NewReader(ctx.hijTLSConn)
		b = false
	default:
		hijConn.Close()
	}
	return
}

func (ctx *Context) doMitm() (w http.ResponseWriter, r *http.Request) {
	req, err := http.ReadRequest(ctx.hijTLSReader)
	if err != nil {
		if !isConnectionClosed(err) {
			ctx.doError("Request", ErrRequestRead, err)
		}
		return
	}
	req.RemoteAddr = ctx.ConnectReq.RemoteAddr
	if req.URL.IsAbs() {
		ctx.doError("Request", ErrAbsURLAfterCONNECT, nil)
		return
	}
	req.URL.Scheme = "https"
	req.URL.Host = ctx.ConnectHost
	w = NewConnResponseWriter(ctx.hijTLSConn)
	r = req
	return
}

func (ctx *Context) doRequest(w http.ResponseWriter, r *http.Request) (bool, error) {
	var err error
	if !r.URL.IsAbs() {
		if r.Body != nil {
			defer r.Body.Close()
		}
		err := ServeInMemory(w, 500, nil, []byte("This is a proxy server. Does not respond to non-proxy requests."))
		if err != nil && !isConnectionClosed(err) {
			ctx.doError("Request", ErrResponseWrite, err)
		}
		return true, err
	}
	r.RequestURI = r.URL.String()
	logging.Printf("DEBUG", "doRequest: New Connection to %s Session ID: %d\n",r.URL.Host,ctx.SessionNo)
        ctx.AccessLog.StartRecord.Proxy, err = os.Hostname()
        ctx.AccessLog.StartRecord.SessionID = ctx.SessionNo
        ctx.AccessLog.StartRecord.State = "start"
        ctx.AccessLog.StartRecord.SourceIP = ctx.Req.RemoteAddr
        ctx.AccessLog.StartRecord.DestinationIP = ""
        if len(ctx.Req.Header.Values("X-Forwarded-For")) > 0 {
        	forwardedValues := ctx.ConnectReq.Header.Values("X-Forwarded-For")
                ctx.AccessLog.StartRecord.ForwardedIP = strings.Join(forwardedValues[:],",")
        } else if len(ctx.Req.Header.Values("Forwarded")) > 0 {
                forwardedValues := ctx.Req.Header.Values("Forwarded")
                ctx.AccessLog.StartRecord.ForwardedIP = strings.Join(forwardedValues[:],",")
        } else {
                ctx.AccessLog.StartRecord.ForwardedIP = ""
        }
        ctx.AccessLog.StartRecord.Method = ctx.Req.Method
        ctx.AccessLog.StartRecord.Scheme = ctx.Req.URL.Scheme
        ctx.AccessLog.StartRecord.Url = ctx.Req.URL.String()
        ctx.AccessLog.StartRecord.Version = ctx.Req.Proto
        ctx.AccessLog.StartRecord.Status = ""
        ctx.AccessLog.StartRecord.BytesIN = 0
        ctx.AccessLog.StartRecord.BytesOUT = 0
        ctx.AccessLog.StartRecord.Protocol = ""
        ctx.AccessLog.StartRecord.Starttime = time.Now()
        ctx.AccessLog.StartRecord.Endtime = time.Now()
        ctx.AccessLog.StartRecord.Duration = time.Duration(0)
        ctx.AccessLog.EndRecord = ctx.AccessLog.StartRecord
        ctx.AccessLog.EndRecord.State = "end"
	if ctx.Prx.OnRequest == nil {
		return false, nil
	}
	resp := ctx.onRequest(r)
	if resp == nil {
		return false, nil
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	resp.Request = r
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	err = ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Request", ErrResponseWrite, err)
	}
	return true, err
}

func (ctx *Context) doResponse(w http.ResponseWriter, r *http.Request) error {
	if r.Body != nil {
		defer r.Body.Close()
	}

	resp, err := ctx.Prx.Rt.RoundTrip(r)
        ctx.AccessLog.StartRecord.Status = resp.Status
        ctx.AccessLog.EndRecord.Status = ctx.AccessLog.StartRecord.Status
	bodySize := r.ContentLength
	// Calculate the size of the headers 
	headersSize := 0 
	for name, values := range r.Header { 
		for _, value := range values {
			headersSize += len(name) + len(value) + len(": ") + len("\r\n")
		}
	}
	// Adding the size of the initial request line and the final empty line 
	requestLineSize := len(r.Method) + len(r.URL.String()) + len(" HTTP/1.1\r\n")
	finalEmptyLineSize := len("\r\n") 
	// Calculate the total request size 
	totalSize := requestLineSize + headersSize + int(bodySize) + finalEmptyLineSize
        ctx.AccessLog.EndRecord.BytesOUT = ctx.AccessLog.EndRecord.BytesOUT + int64(totalSize)
	logging.AccesslogWrite(ctx.AccessLog.StartRecord)
	if err != nil {
		if err != context.Canceled && !isConnectionClosed(err) {
			ctx.doError("Response", ErrRoundTrip, err)
		}
		err := ServeInMemory(w, 404, nil, nil)
		if err != nil && !isConnectionClosed(err) {
			ctx.doError("Response", ErrResponseWrite, err)
                } else {
                        logging.Printf("DEBUG", "doResponse: Connection closed. Session ID: %d\n",ctx.SessionNo)
			ctx.AccessLog.EndRecord.Endtime = time.Now()
			ctx.AccessLog.EndRecord.Duration = ctx.AccessLog.EndRecord.Endtime.Sub(ctx.AccessLog.EndRecord.Starttime)
			bodySize := resp.ContentLength
			// Calculate the size of the headers 
			headersSize := 0 
			for name, values := range resp.Header { 
				for _, value := range values {
					headersSize += len(name) + len(value) + len(": ") + len("\r\n")
				}
			}
			// Calculate the total request size 
			totalSize := headersSize + int(bodySize)
	        	ctx.AccessLog.EndRecord.BytesIN = ctx.AccessLog.EndRecord.BytesIN + int64(totalSize)
			logging.AccesslogWrite(ctx.AccessLog.EndRecord)
                }
		return err
	}
	if ctx.Prx.OnResponse != nil {
		ctx.onResponse(r, resp)
	}
	resp.Request = r
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	err = ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Response", ErrResponseWrite, err)
        } else {
                logging.Printf("DEBUG", "doResponse: Connection closed. Session ID: %d\n",ctx.SessionNo)
		ctx.AccessLog.EndRecord.Endtime = time.Now()
		ctx.AccessLog.EndRecord.Duration = ctx.AccessLog.EndRecord.Endtime.Sub(ctx.AccessLog.EndRecord.Starttime)
		bodySize := resp.ContentLength
		// Calculate the size of the headers 
		headersSize := 0 
		for name, values := range resp.Header { 
			for _, value := range values {
				headersSize += len(name) + len(value) + len(": ") + len("\r\n")
			}
		}
		// Calculate the total request size 
		totalSize := headersSize + int(bodySize)
	        ctx.AccessLog.EndRecord.BytesIN = ctx.AccessLog.EndRecord.BytesIN + int64(totalSize)
		logging.AccesslogWrite(ctx.AccessLog.EndRecord)
        }
	return err
}
