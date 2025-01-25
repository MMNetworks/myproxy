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
)

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
	AccessLog logging.AccessLogRecord

	// User data to use free.
	UserData interface{}

	hijTLSConn   *tls.Conn
	hijTLSReader *bufio.Reader
}

func (ctx *Context) onAccept(w http.ResponseWriter, r *http.Request) bool {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Accept", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnAccept(ctx, w, r)
}

func (ctx *Context) onAuth(authType string, user string, pass string) bool {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Auth", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnAuth(ctx, authType, user, pass)
}

func (ctx *Context) onConnect(host string) (ConnectAction ConnectAction,
	newHost string) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Connect", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnConnect(ctx, host)
}

func (ctx *Context) onRequest(req *http.Request) (resp *http.Response) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Request", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnRequest(ctx, req)
}

func (ctx *Context) onResponse(req *http.Request, resp *http.Response) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Response", ErrPanic, err)
		}
	}()
	ctx.Prx.OnResponse(ctx, req, resp)
}

func (ctx *Context) doError(where string, err *Error, opErr error) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	if ctx.Prx.OnError == nil {
		return
	}
	ctx.Prx.OnError(ctx, where, err, opErr)
}

func (ctx *Context) doAccept(w http.ResponseWriter, r *http.Request) bool {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
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
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
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
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())

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
		ctx.AccessLog.Status = "500 internal error ErrNotSupportHijacking"
		ctx.AccessLog.Endtime = time.Now()
		ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
		logging.AccesslogWrite(ctx.AccessLog)
		return
	}
	conn, _, err := hij.Hijack()
	if err != nil {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Connect", ErrNotSupportHijacking, err)
		ctx.AccessLog.Status = "500 internal error ErrNotSupportHijacking"
		ctx.AccessLog.Endtime = time.Now()
		ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
		logging.AccesslogWrite(ctx.AccessLog)
		return
	}
	hijConn := conn
	ctx.AccessLog.ProxyIP = hijConn.LocalAddr().String()
	ctx.AccessLog.SourceIP = hijConn.RemoteAddr().String()
	ctx.AccessLog.UpstreamProxyIP = ""
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
			ctx.AccessLog.Status = "404 " + err.Error()
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.AccesslogWrite(ctx.AccessLog)
			return
		}
		remoteConn := conn.(*net.TCPConn)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			remoteConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrResponseWrite, err)
				ctx.AccessLog.Status = "500 " + err.Error()
				ctx.AccessLog.Endtime = time.Now()
				ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
				logging.AccesslogWrite(ctx.AccessLog)
			}
			return
		}
		if ctx.AccessLog.Status == "" {
			// Proxy Dial sets status if a proxy is used
			ctx.AccessLog.Status = "200 OK"
		}
		logging.Printf("DEBUG", "doConnect: New Connection to %s Session ID: %d\n", host, ctx.SessionNo)
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
					ctx.AccessLog.Status = "500 " + err.Error()
				}
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
					protocol, description := protocol.AnalyseFirstPacket(buf[:n])
					if protocol != "Unknown" {
						if protocol != "TLS" {
							logging.Printf("INFO", "doConnect: Found tunnelled protocol in request: %s %s\n", protocol, description)
							ctx.AccessLog.Protocol = protocol
						} else {
							logging.Printf("INFO", "doConnect: Found in request: %s %s\n", protocol, description)
							spos := strings.Index(description, ":")
							ctx.AccessLog.Protocol = protocol + ":" + description[spos+2:]
						}
					}
				}
				FirstPacket = false
				ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + int64(n)
			}
			n, err := io.Copy(remoteConn, hijConn)
			ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + n
			if err != nil {
				panic(err)
			}
			remoteConn.CloseWrite()
			if c, ok := hijConn.(*net.TCPConn); ok {
				c.CloseRead()
			}
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
					ctx.AccessLog.Status = "500 " + err.Error()
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
					protocol, description := protocol.AnalyseFirstPacketResponse(buf[:n])
					if protocol != "Unknown" {
						logging.Printf("INFO", "doConnect: Found tunnelled protocol in response: %s %s\n", protocol, description)
						ctx.AccessLog.Protocol = protocol
					}
				}
				FirstPacketResponse = false
				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(n)
			}
			n, err := io.Copy(hijConn, remoteConn)
			ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + n
			if err != nil {
				panic(err)
			}
			remoteConn.CloseRead()
			if c, ok := hijConn.(*net.TCPConn); ok {
				c.CloseWrite()
			}
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
			ctx.AccessLog.Status = "500 " + err.Error()
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.AccesslogWrite(ctx.AccessLog)
			return
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, *cert)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrResponseWrite, err)
				ctx.AccessLog.Status = "500 " + err.Error()
			}
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.AccesslogWrite(ctx.AccessLog)
			return
		}
		ctx.hijTLSConn = tls.Server(hijConn, tlsConfig)
		if err := ctx.hijTLSConn.Handshake(); err != nil {
			ctx.hijTLSConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrTLSHandshake, err)
				ctx.AccessLog.Status = "500 " + err.Error()
			}
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.AccesslogWrite(ctx.AccessLog)
			return
		}
		ctx.hijTLSReader = bufio.NewReader(ctx.hijTLSConn)
		b = false
	default:
		hijConn.Close()
	}
	logging.Printf("DEBUG", "doConnect: Connection closed. Session ID: %d\n", ctx.SessionNo)
	ctx.AccessLog.Endtime = time.Now()
	ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
	logging.AccesslogWrite(ctx.AccessLog)
	return
}

func (ctx *Context) doMitm() (w http.ResponseWriter, r *http.Request) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
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
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
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
	logging.Printf("DEBUG", "doRequest: New Connection to %s Session ID: %d\n", r.URL.Host, ctx.SessionNo)
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
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	if r.Body != nil {
		defer r.Body.Close()
	}

	resp, err := ctx.Prx.Rt.RoundTrip(r)
	bodySize := r.ContentLength
	
	headersSize := 0
	for name, values := range r.Header {
		for _, value := range values {
			headersSize += len(name) + len(value) + len(": ") + len("\r\n")
		}
	}
	// it seems host header information is moved to different entries in structure 
	if r.Host == "" {
		headersSize += len("Host: ") + len(r.URL.Host) + len("\r\n")
	} else {
		headersSize += len("Host: ") + len(r.Host) + len("\r\n")
	}
	// added by roundtripper in transport request as extra header.
	headersSize += len("Accept-Encoding: gzip\r\n")
	// Adding the size of the initial request line and the final empty line
	requestLineSize := len(r.Method) + 1 + len(r.URL.Path) + len(" HTTP/1.1\r\n")
	finalEmptyLineSize := len("\r\n")
	// Calculate the total request size
	totalSize := requestLineSize + headersSize + int(bodySize) + finalEmptyLineSize
	ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + int64(totalSize)
	if err != nil {
		if err != context.Canceled && !isConnectionClosed(err) {
			ctx.doError("Response", ErrRoundTrip, err)
		}
		ctx.AccessLog.Status = "404 " + err.Error()
		err := ServeInMemory(w, 404, nil, nil)
		if err != nil && !isConnectionClosed(err) {
			ctx.doError("Response", ErrResponseWrite, err)
		} else {
			logging.Printf("DEBUG", "doResponse: Connection closed. Session ID: %d\n", ctx.SessionNo)
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.AccesslogWrite(ctx.AccessLog)
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
		ctx.AccessLog.Status = "500 " + err.Error()
	} else {
		logging.Printf("DEBUG", "doResponse: Connection closed. Session ID: %d\n", ctx.SessionNo)
		ctx.AccessLog.Status = resp.Status
		bodySize := resp.ContentLength
		// Calculate the size of the headers
		headersSize := 0
		for name, values := range resp.Header {
			for _, value := range values {
		                if strings.ToUpper(name) != "VIA" {	
					headersSize += len(name) + len(value) + len(": ") + len("\r\n")
				}
			}
		}
		headerEmptyLineSize := len("\r\n")
		responseLineSize := len(resp.Status) + len(" HTTP/1.1\r\n")
		// Calculate the total request size
		totalSize := responseLineSize + headersSize + headerEmptyLineSize + int(bodySize)
		ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(totalSize)
	}
	ctx.AccessLog.Endtime = time.Now()
	ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
	logging.AccesslogWrite(ctx.AccessLog)
	return err
}
