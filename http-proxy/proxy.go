package httpproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"myproxy/logging"
	"myproxy/protocol"
	"myproxy/readconfig"
	"myproxy/viruscheck"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Proxy defines parameters for running an HTTP Proxy. It implements
// http.Handler interface for ListenAndServe function. If you need, you must
// set Proxy struct before handling requests.
type Proxy struct {
	// Session number of last proxy request.
	SessionNo int64

	// RoundTripper interface to obtain remote response.
	// By default, it uses &http.Transport{}.
	Rt http.RoundTripper

	// RoundTripper interface to obtain remote response.
	// By default, it uses &http.Transport{}.
	Dial func(ctx *Context, network string, address string) (net.Conn, error)

	// Certificate key pair.
	Ca tls.Certificate

	// User data to use free.
	UserData interface{}

	// Error callback.
	OnError func(ctx *Context, where string, err *Error, opErr error)

	// Accept callback. It greets proxy request like ServeHTTP function of
	// http.Handler.
	// If it returns true, stops processing proxy request.
	OnAccept func(ctx *Context, w http.ResponseWriter, r *http.Request) bool

	// Auth callback. If you need authentication, set this callback.
	// If it returns true, authentication succeeded.
	OnAuth func(ctx *Context, authType string, user string, pass string) bool

	// Connect callback. It sets connect action and new host.
	// If len(newhost) > 0, host changes.
	OnConnect func(ctx *Context, host string) (ConnectAction ConnectAction,
		newHost string)

	// Request callback. It greets remote request.
	// If it returns non-nil response, stops processing remote request.
	OnRequest func(ctx *Context, req *http.Request) (resp *http.Response)

	// Response callback. It greets remote response.
	// Remote response sends after this callback.
	OnResponse func(ctx *Context, req *http.Request, resp *http.Response)

	// If ConnectAction is ConnectMitm, it sets chunked to Transfer-Encoding.
	// By default, true.
	MitmChunked bool

	// HTTP Authentication type. If it's not specified (""), uses "Basic".
	// By default, "".
	AuthType string

	// clamd Client
	ClamdStruct *viruscheck.ClamdStruct

	signer *CaSigner
}

// var ctx *Context

//func GetContext() *Context {
//	return ctx
//}

// NewProxy returns a new Proxy has default CA certificate and key.
func NewProxy() (*Proxy, error) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	return NewProxyCert(nil, nil)
}

// NewProxyCert returns a new Proxy given CA certificate and key.
func NewProxyCert(caCert, caKey []byte) (*Proxy, error) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())

	prx := &Proxy{
		Rt:          http.DefaultTransport,
		MitmChunked: true,
		signer:      NewCaSignerCache(1024),
	}

	prx.Dial = NetDial

	prx.signer.Ca = &prx.Ca
	if caCert == nil {
		caCert = DefaultCaCert
	}
	if caKey == nil {
		caKey = DefaultCaKey
	}
	var err error
	prx.Ca, err = tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return nil, err
	}
	return prx, nil
}

func NetDial(ctx *Context, network, address string) (net.Conn, error) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())

	var timeOut time.Duration = time.Duration(readconfig.Config.Connection.Timeout)
	var keepAlive time.Duration = time.Duration(readconfig.Config.Connection.Keepalive)

	newDial := net.Dialer{
		Timeout:   timeOut * time.Second, // Set the timeout duration
		KeepAlive: keepAlive * time.Second,
	}

	conn, err := newDial.Dial("tcp", address)
	if err != nil {
		logging.Printf("ERROR", "NetDial: SessionID:%d Error connecting to address: %s error: %v\n", ctx.SessionNo, address, err)
		return nil, err
	}

	ctx.AccessLog.DestinationIP = conn.RemoteAddr().String()
	return conn, err
}

// ServeHTTP implements http.Handler.
func (prx *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	ctx := &Context{Prx: prx,
		SessionNo:      atomic.AddInt64(&prx.SessionNo, 1),
		TCPState:       &protocol.TCPStruct{},
		WebsocketState: &protocol.WSStruct{},
		Rt:             prx.Rt,
		Dial:           prx.Dial}

	defer func() {
		rec := recover()
		if rec != nil {
			if err, ok := rec.(error); ok && prx.OnError != nil {
				prx.OnError(ctx, "ServeHTTP", ErrPanic, err)
			}
			panic(rec)
		}
	}()
	// Set deafult with NetDial
	ctx.Rt = &http.Transport{TLSClientConfig: &tls.Config{},
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			return NetDial(ctx, network, addr)
		},
		Dial: func(network, addr string) (net.Conn, error) {
			return NetDial(ctx, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		ResponseHeaderTimeout: 3 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	// Initialise access log values
	ctx.AccessLog.Proxy, _ = os.Hostname()
	ctx.AccessLog.SessionID = ctx.SessionNo
	ctx.AccessLog.SourceIP = r.RemoteAddr
	ctx.AccessLog.DestinationIP = ""
	ctx.AccessLog.UserAgent = r.Header.Get("User-Agent")
	ctx.AccessLog.ForwardedIP = ""
	if len(r.Header.Values("X-Forwarded-For")) > 0 {
		forwardedValues := r.Header.Values("X-Forwarded-For")
		ctx.AccessLog.ForwardedIP = strings.Join(forwardedValues[:], ",")
	} else if len(r.Header.Values("Forwarded")) > 0 {
		forwardedValues := r.Header.Values("Forwarded")
		ctx.AccessLog.ForwardedIP = strings.Join(forwardedValues[:], ",")
	}
	ctx.AccessLog.UpstreamProxyIP = ""
	ctx.AccessLog.Method = r.Method
	ctx.AccessLog.Scheme = r.URL.Scheme
	ctx.AccessLog.Url = r.URL.Redacted()
	ctx.AccessLog.Version = r.Proto
	ctx.AccessLog.Status = ""
	ctx.AccessLog.BytesIN = 0
	ctx.AccessLog.BytesOUT = 0
	ctx.AccessLog.Protocol = ""
	ctx.AccessLog.Starttime = time.Now()
	ctx.AccessLog.Endtime = time.Now()
	ctx.AccessLog.Duration = time.Duration(0)
	addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		prx.OnError(ctx, "ServeHTTP", ErrPanic, errors.New("Can't get local Address"))
		return
	}

	// Get the local address from the connection
	localAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		prx.OnError(ctx, "ServeHTTP", ErrPanic, errors.New("Can't get local Address"))
		return
	}
	ctx.AccessLog.ProxyIP = localAddr.String()

	logging.AccesslogWriteStart(ctx.AccessLog)

	if ctx.doAccept(w, r) {
		return
	}

	if ctx.doAuth(w, r) {
		return
	}
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")

	if b := ctx.doConnect(w, r); b {
		// logging.Printf("DEBUG", "ServeHTTP: SessionID:%d doConnect %t\n", ctx.SessionNo,b)
		return
	}
	logging.Printf("DEBUG", "ServeHTTP: SessionID:%d doConnect %t\n", ctx.SessionNo, false)

	for {
		var w2 = w
		var r2 = r
		var cyclic = false

		// logging.Printf("DEBUG", "ServeHTTP: SessionID:%d ConnectAction: %v\n", ctx.SessionNo,ctx.ConnectAction)
		switch ctx.ConnectAction {
		case ConnectMitm:
			if prx.MitmChunked {
				cyclic = true
			}
			// logging.Printf("DEBUG", "ServeHTTP: SessionID:%d Call doMitm\n", ctx.SessionNo)
			w2, r2 = ctx.doMitm()
		}
		if w2 == nil || r2 == nil {
			if w2 == nil {
				// logging.Printf("DEBUG", "ServeHTTP: SessionID:%d doMitm w2 == nil \n", ctx.SessionNo)
			}
			if r2 == nil {
				// logging.Printf("DEBUG", "ServeHTTP: SessionID:%d doMitm r2 == nil \n", ctx.SessionNo)
			}
			break
		}
		//r.Header.Del("Accept-Encoding")
		//r.Header.Del("Connection")
		ctx.SubSessionNo++
		if b, err := ctx.doRequest(w2, r2); err != nil {
			// logging.Printf("DEBUG", "ServeHTTP: SessionID:%d doRequest: %t Error: %v\n", ctx.SessionNo,b,err)
			break
		} else {
			// logging.Printf("DEBUG", "ServeHTTP: SessionID:%d doRequest: %t\n", ctx.SessionNo,b)
			if b {
				if !cyclic {
					break
				} else {
					continue
				}
			}
		}
		if err := ctx.doResponse(w2, r2); err != nil || !cyclic {
			// logging.Printf("DEBUG", "ServeHTTP: SessionID:%d doResponse Error: %v\n", ctx.SessionNo,err)
			break
		}
	}

	if ctx.hijTLSConn != nil {
		ctx.hijTLSConn.Close()
	}
}
