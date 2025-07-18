package httpproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"myproxy/logging"
	"myproxy/readconfig"
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
	var timeOut time.Duration = time.Duration(readconfig.Config.Connection.Timeout)
	var keepAlive time.Duration = time.Duration(readconfig.Config.Connection.Keepalive)

	prx := &Proxy{
		Rt: &http.Transport{TLSClientConfig: &tls.Config{},
			//			Proxy: http.ProxyFromEnvironment,
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				logging.Printf("TRACE", "myproxy/http-proxy.NewProxyCert.Transport.DialContext: called\n")
				conn, err := (&net.Dialer{
					Timeout:   timeOut * time.Second,
					KeepAlive: keepAlive * time.Second,
				}).DialContext(dctx, network, addr)
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
			Dial: func(network, addr string) (net.Conn, error) {
				logging.Printf("TRACE", "myproxy/http-proxy.NewProxyCert.Transport.Dial: called\n")
				conn, err := (&net.Dialer{
					Timeout:   timeOut * time.Second,
					KeepAlive: keepAlive * time.Second,
				}).Dial(network, addr)
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
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
		ctx.AccessLog.Status = "500 internal error"
		return nil, err
	}
	ctx.AccessLog.UpstreamProxyIP = ""
	ctx.AccessLog.Status = "200 connected to " + conn.RemoteAddr().String()
	ctx.AccessLog.DestinationIP = conn.RemoteAddr().String()

	return conn, err
}

// ServeHTTP implements http.Handler.
func (prx *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	cprx := &Proxy{
		SessionNo:   prx.SessionNo,
		Rt:          prx.Rt,
		Dial:        prx.Dial,
		Ca:          prx.Ca,
		UserData:    prx.UserData,
		OnError:     prx.OnError,
		OnAccept:    prx.OnAccept,
		OnAuth:      prx.OnAuth,
		OnConnect:   prx.OnConnect,
		OnRequest:   prx.OnRequest,
		OnResponse:  prx.OnResponse,
		MitmChunked: prx.MitmChunked,
		AuthType:    prx.AuthType,
		signer:      prx.signer,
	}
	ctx := &Context{Prx: cprx, SessionNo: atomic.AddInt64(&prx.SessionNo, 1)}

	defer func() {
		rec := recover()
		if rec != nil {
			if err, ok := rec.(error); ok && prx.OnError != nil {
				prx.OnError(ctx, "ServeHTTP", ErrPanic, err)
			}
			panic(rec)
		}
	}()
	// Ensure cleanup is performed when the function exits
	defer func() {
		logging.Printf("DEBUG", "ServeHTTP: cleanup cprx SessionID:%d\n", cprx.SessionNo)
		cprx.Rt = nil
		cprx.Dial = nil
		cprx.UserData = nil
		cprx.OnError = nil
		cprx.OnAccept = nil
		cprx.OnAuth = nil
		cprx.OnConnect = nil
		cprx.OnRequest = nil
		cprx.OnResponse = nil
		cprx.signer = nil
		cprx = nil
	}()
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
	ctx.AccessLog.Url = r.URL.String()
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
		return
	}

	for {
		var w2 = w
		var r2 = r
		var cyclic = false
		switch ctx.ConnectAction {
		case ConnectMitm:
			if prx.MitmChunked {
				cyclic = true
			}
			w2, r2 = ctx.doMitm()
		}
		if w2 == nil || r2 == nil {
			break
		}
		//r.Header.Del("Accept-Encoding")
		//r.Header.Del("Connection")
		ctx.SubSessionNo++
		if b, err := ctx.doRequest(w2, r2); err != nil {
			break
		} else {
			if b {
				if !cyclic {
					break
				} else {
					continue
				}
			}
		}
		if err := ctx.doResponse(w2, r2); err != nil || !cyclic {
			break
		}
	}

	if ctx.hijTLSConn != nil {
		ctx.hijTLSConn.Close()
	}
}
