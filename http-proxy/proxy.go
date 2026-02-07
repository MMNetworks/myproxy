package httpproxy

import (
	dns "codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
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
	"sync"
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

// Define Dialer with Resolvers
type proxyDialer struct {
	resolvers  []string
	timeout    time.Duration
	dnsTimeout time.Duration
	ipv4       bool
	ipv6       bool
	//	LocalAddr     Addr
	fallbackDelay time.Duration
	keepAlive     time.Duration
}

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

	var dnsTimeOut time.Duration = time.Duration(readconfig.Config.Connection.DNSTimeout)
	var timeOut time.Duration = time.Duration(readconfig.Config.Connection.Timeout)
	var keepAlive time.Duration = time.Duration(readconfig.Config.Connection.Keepalive)
	var fallbackTime time.Duration = time.Duration(*readconfig.Config.Connection.FallbackTime)

	start := time.Now()
	var conn net.Conn
	var err error

	logging.Printf("DEBUG", "NetDial: SessionID:%d Connecting to address: %s\n", ctx.SessionNo, address)

	if len(readconfig.Config.Connection.DNSServers) > 0 {
		// Custom resolver that forces configred DNS servers
		// Need round robin and stickyness
		//
		pDialer := proxyDialer{
			resolvers:     readconfig.Config.Connection.DNSServers,
			timeout:       timeOut * time.Second,
			fallbackDelay: fallbackTime * time.Millisecond,
			keepAlive:     keepAlive * time.Second,
			dnsTimeout:    dnsTimeOut * time.Second,
			ipv4:          *readconfig.Config.Connection.IPv4,
			ipv6:          *readconfig.Config.Connection.IPv6,
		}
		conn, err = pDialer.Dial(ctx, "tcp", address)
	} else {
		newDial := net.Dialer{
			Timeout:   timeOut * time.Second, // Set the timeout duration
			KeepAlive: keepAlive * time.Second,
		}
		conn, err = newDial.Dial("tcp", address)
	}
	elapsed := time.Since(start)
	if err != nil {
		logging.Printf("ERROR", "NetDial: SessionID:%d Error connecting to address: %s elapsed time: %v error: %v\n", ctx.SessionNo, address, elapsed, err)
		return nil, err
	}
	logging.Printf("DEBUG", "NetDial: SessionID:%d Connected to ip: %s elapsed time: %v\n", ctx.SessionNo, conn.RemoteAddr().String(), elapsed)

	ctx.AccessLog.DestinationIP = conn.RemoteAddr().String()
	return conn, err
}

func (pd *proxyDialer) queryResolvers(ctx *Context, name string) ([]string, string, error) {
	if len(pd.resolvers) == 0 {
		logging.Printf("ERROR", "queryResolvers: SessionID:%d No resolvers configured\n", ctx.SessionNo)
		return nil, "", errors.New("no resolvers configured")
	}

	type res struct {
		ips    []string
		server string
		err    error
	}
	ch := make(chan res, len(pd.resolvers))

	ctxResolvers, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, r := range pd.resolvers {
		resolver := r
		go func() {
			ips, err := pd.queryResolver(ctx, ctxResolvers, resolver, name)
			select {
			case ch <- res{ips, resolver, err}:
			case <-ctxResolvers.Done():
			}
		}()
	}

	var firstErr error
	for i := 0; i < len(pd.resolvers); i++ {
		select {
		case r := <-ch:
			if r.err == nil && len(r.ips) > 0 {
				cancel()
				return r.ips, r.server, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
		case <-ctxResolvers.Done():
			return nil, "", ctxResolvers.Err()
		}
	}

	if firstErr == nil {
		firstErr = errors.New("all resolvers returned empty answers")
		logging.Printf("ERROR", "resolveRace: SessionID:%d All resolvers returned empty answers\n", ctx.SessionNo)
	}
	return nil, "all", firstErr
}

func (pd *proxyDialer) queryResolver(ctx *Context, ctxResolvers context.Context, resolver, name string) ([]string, error) {
	var ips []string

	ipsv6, err1 := pd.queryRecord(ctx, ctxResolvers, resolver, name, dns.TypeAAAA)
	ipsv4, err2 := pd.queryRecord(ctx, ctxResolvers, resolver, name, dns.TypeA)

	if err1 != nil && err1 != context.Canceled && err1 != context.DeadlineExceeded {
		logging.Printf("ERROR", "queryResolver: SessionID:%d No AAAA answers from %s error: %v\n", ctx.SessionNo, resolver, err1)
	}
	if err1 != nil && err2 != context.Canceled && err2 != context.DeadlineExceeded {
		logging.Printf("ERROR", "queryResolver: SessionID:%d No A answers from %s error: %v\n", ctx.SessionNo, resolver, err2)
	}
	if err1 != nil && err2 != nil {
		if err1 != context.Canceled && err1 != context.DeadlineExceeded && err2 != context.Canceled && err2 != context.DeadlineExceeded {
			logging.Printf("ERROR", "queryResolver: SessionID:%d No A/AAAA answers from %s\n", ctx.SessionNo, resolver)
			return nil, errors.New("no A/AAAA answer")
		} else {
			logging.Printf("DEBUG", "queryResolver: SessionID:%d No AAAA answers from %s error: context was canceled\n", ctx.SessionNo, resolver)
			return nil, context.Canceled
		}
	}
	if len(ipsv6) == 0 && len(ipsv4) == 0 {
		logging.Printf("ERROR", "queryResolver: SessionID:%d No A/AAAA answers from %s error: empty answers\n", ctx.SessionNo, resolver)
		return nil, errors.New("no A/AAAA answer")

	}
	ips = append(ips, ipsv6...)
	ips = append(ips, ipsv4...)
	return ips, nil
}

func (pd *proxyDialer) queryRecord(ctx *Context, ctxResolvers context.Context, resolver, name string, qtype uint16) ([]string, error) {
	m := dns.NewMsg(ensureDot(name), qtype)
	c := dns.NewClient()

	var cancel context.CancelFunc
	if pd.dnsTimeout > 0 {
		ctxResolvers, cancel = context.WithTimeout(ctxResolvers, pd.dnsTimeout)
		defer cancel()
	}

	start := time.Now()
	r, _, err := c.Exchange(ctxResolvers, m, "udp", resolver)
	if err != nil {
		if err == context.Canceled || err == context.DeadlineExceeded {
			logging.Printf("DEBUG", "queryRecord: SessionID:%d Resolver %s error: udp context was canceled\n", ctx.SessionNo, resolver)
			return nil, ctxResolvers.Err()
		} else {
			logging.Printf("ERROR", "queryRecord: SessionID:%d udp exchange failed from %s for %s error: %v\n", ctx.SessionNo, resolver, dns.TypeToString[qtype], err)
			return nil, errors.New("udp exchange failed")
		}
	}
	elapsedUDP := time.Since(start)

	if r.Truncated {
		logging.Printf("DEBUG", "queryRecord: SessionID:%d udp response truncated from %s for %s; failing back to tcp elapsed time: %v\n", ctx.SessionNo, resolver, dns.TypeToString[qtype], elapsedUDP)
		start := time.Now()
		r, _, err = c.Exchange(ctxResolvers, m, "tcp", resolver)
		elapsedTCP := time.Since(start)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				logging.Printf("DEBUG", "queryRecord: SessionID:%d Resolver %s error: tcp context was canceled\n", ctx.SessionNo, resolver)
				return nil, ctxResolvers.Err()
			} else {
				logging.Printf("ERROR", "queryRecord: SessionID:%d tcp exchange failed after truncation from %s for %s elapsed time: %v  error: %v\n", ctx.SessionNo, resolver, dns.TypeToString[qtype], elapsedTCP, err)
				return nil, errors.New("tcp exchange failed after truncation")
			}
		}
	}

	if r.Rcode != dns.RcodeSuccess {
		logging.Printf("ERROR", "queryRecord: SessionID:%d Resolver rcode: %s from: %s for %s\n", ctx.SessionNo, dns.RcodeToString[r.Rcode], resolver, dns.TypeToString[qtype])
		return nil, errors.New("rcode!=success")
	}

	var out []string
	for _, rr := range r.Answer {
		switch x := rr.(type) {
		case *dns.A:
			if ad, ok := x.Data().(rdata.A); ok {
				out = append(out, ad.Addr.String())
			}
		case *dns.AAAA:
			if ad, ok := x.Data().(rdata.AAAA); ok {
				out = append(out, ad.Addr.String())
			}
		}
	}
	return out, nil
}

func ensureDot(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// Dial implements Dialer with provided resolvers
func (pd *proxyDialer) Dial(ctx *Context, network, address string) (net.Conn, error) {
	var Mu sync.Mutex
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		logging.Printf("ERROR", "Dial: SessionID:%d Error connecting to address: %s error: %v\n", ctx.SessionNo, address, err)
		return nil, errors.New("invalid address")
	}
	if ip := net.ParseIP(host); ip != nil {
		logging.Printf("DEBUG", "Dial: SessionID:%d Host %s is already an IP address\n", ctx.SessionNo, ip.String())
		newDial := net.Dialer{
			Timeout:   pd.timeout,
			KeepAlive: pd.keepAlive,
		}
		return newDial.Dial(network, address)
	}

	start := time.Now()
	ips, dnsServer, err := pd.queryResolvers(ctx, host)
	elapsed := time.Since(start)
	if err != nil {
		logging.Printf("ERROR", "Dial: SessionID:%d Failed to resolve host: %s resolver: %s elapsed time: %v error: %v\n", ctx.SessionNo, host, dnsServer, elapsed, err)
		return nil, errors.New("resolve failed")
	}
	if len(ips) <= 0 {
		logging.Printf("DEBUG", "Dial: SessionID:%d Resolver %s resolved host %s to no ip in %v\n", ctx.SessionNo, dnsServer, host, elapsed)
		return nil, errors.New("resolved to no IPs")
	}
	logging.Printf("DEBUG", "Dial: SessionID:%d Resolver %s resolved host %s to ips: %v elapsed time: %v\n", ctx.SessionNo, dnsServer, host, ips, elapsed)

	dctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var lastErr error
	var wg sync.WaitGroup
	result := make(chan net.Conn, 1)

	var haveIPv6IP bool = false
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.To4() == nil {
			haveIPv6IP = true
		}
	}
	start = time.Now()
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			logging.Printf("DEBUG", "Dial: SessionID:%d Skipping invalid ip %s\n", ctx.SessionNo, ipStr)
			continue
		}
		if ip.To4() != nil {
			if !pd.ipv4 {
				logging.Printf("DEBUG", "Dial: SessionID:%d Skipping IPv4 ip %s\n", ctx.SessionNo, ipStr)
				continue
			}
			if pd.ipv6 && haveIPv6IP {
				logging.Printf("DEBUG", "Dial: SessionID:%d Trying IPv4 ip %s after delay of %v\n", ctx.SessionNo, ipStr, pd.fallbackDelay)
			} else {
				logging.Printf("DEBUG", "Dial: SessionID:%d Trying IPv4 ip %s\n", ctx.SessionNo, ipStr)
			}
		} else {
			if !pd.ipv6 {
				logging.Printf("DEBUG", "Dial: SessionID:%d Skipping IPv6 ip %s\n", ctx.SessionNo, ipStr)
				continue
			}
			logging.Printf("DEBUG", "Dial: SessionID:%d Trying IPv6 ip %s\n", ctx.SessionNo, ipStr)
		}

		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()

			address := net.JoinHostPort(ip.String(), port)
			dialer := &net.Dialer{
				Timeout:   pd.timeout,
				KeepAlive: pd.keepAlive,
			}

			if ip.To4() != nil {
				if pd.fallbackDelay > 0 && pd.ipv6 && haveIPv6IP {
					time.Sleep(pd.fallbackDelay)
				}
			}
			conn, err := dialer.DialContext(dctx, "tcp", address)
			if err == nil {
				select {
				case result <- conn:
					cancel()
				default:
					conn.Close()
				}
			} else {
				if dctx.Err() == context.Canceled || dctx.Err() == context.DeadlineExceeded {
					logging.Printf("DEBUG", "Dial: SessionID:%d Connecting to address %s context was canceled\n", ctx.SessionNo, address)
				} else {
					logging.Printf("ERROR", "Dial: SessionID:%d Error connecting to address %s error: %v\n", ctx.SessionNo, address, err)
				}
				Mu.Lock()
				lastErr = err
				Mu.Unlock()
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(result)
	}()

	connLocal, ok := <-result
	if ok {
		if connLocal != nil {
			elapsed := time.Since(start)
			logging.Printf("DEBUG", "Dial: SessionID:%d Dialed host: %s ip: %s elapsed time: %v\n", ctx.SessionNo, host, connLocal.RemoteAddr().String(), elapsed)
			return connLocal, nil
		}
	}
	elapsed = time.Since(start)
	Mu.Lock()
	logging.Printf("ERROR", "Dial: SessionID:%d Connect failed to host: %s ips: %v elapsed time: %v error: %v\n", ctx.SessionNo, host, ips, elapsed, lastErr)
	Mu.Unlock()
	return nil, errors.New("connect failed to all resolved IPs")

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
