package service

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"io"
	"log"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/protocol"
	"myproxy/readconfig"
	"myproxy/upstream"
	"myproxy/upstream/authenticate"
	"myproxy/viruscheck"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	// "github.com/yassinebenaid/godump"
)

// OnError Error callback.
func OnError(ctx *httpproxy.Context, where string,
	err *httpproxy.Error, opErr error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	logging.Printf("ERROR", "OnError: SessionID:%d %s: %s [%v]\n", ctx.SessionNo, where, err, opErr)
	// panic(err)
}

func setTLSBreak(ctx *httpproxy.Context) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	if readconfig.Config.MITM.Enable {
		readconfig.Config.MITM.Mu.Lock()
		if len(readconfig.Config.MITM.Rules) == 0 {
			// Empty Include/Exclude list => TLS break all
			ctx.TLSBreak = true
		}
		for _, rule := range readconfig.Config.MITM.Rules {
			// IncExc string format (!|)src,(client|proxy);regex,rootCA
			logging.Printf("DEBUG", "setTLSBreak: SessionID:%d Check against rule entry: %s,%s,%s,%s\n", ctx.SessionNo, rule.IP, rule.Client, rule.Regex, rule.TLSConfig.CAbundle)
			// Skip empty or whitespace-only rules
			if strings.TrimSpace(rule.IP) == "" {
				continue
			}
			tlsBreak := doTLSBreak(ctx, rule)
			if tlsBreak < 0 {
				ctx.TLSBreak = false
				break
			} else if tlsBreak > 0 {
				ctx.TLSBreak = true
				break
			}
		}
		readconfig.Config.MITM.Mu.Unlock()
	}
	var status string
	if ctx.TLSBreak {
		status = "enabled"
	} else {
		status = "disabled"
	}
	tU := httpproxy.CleanUntrustedString(ctx, "URL Redacted", ctx.Req.URL.Redacted())
	logging.Printf("INFO", "setTLSBreak: SessionID:%d TLS Break for URL %s: %s\n", ctx.SessionNo, tU, status)
}

func doTLSBreak(ctx *httpproxy.Context, rule readconfig.MitmRule) int {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var connectionIP string = ctx.AccessLog.SourceIP
	var forwardedIP string = ctx.AccessLog.ForwardedIP
	var uri string = ctx.Req.URL.String()
	var uriRedacted string = httpproxy.CleanUntrustedString(ctx, "URL Redacted", ctx.Req.URL.Redacted())
	var matchConn = false
	var matchForw = false
	var checkClient = true
	var checkProxy = true
	var incExcRex string

	// Parse Include/Exclude line

	ctx.TLSConfig = rule.TLSConf

	// Match URL against regex
	matchURI, err := regexp.MatchString(rule.Regex, uri)
	if err != nil {
		logging.Printf("ERROR", "doTLSBreak: SessionID:%d Invalid regex: %s error: %v\n", ctx.SessionNo, incExcRex, err)
		return 0
	}
	if !matchURI {
		logging.Printf("DEBUG", "doTLSBreak: SessionID:%d Regex does not match. regex: %s URI: %s\n", ctx.SessionNo, incExcRex, uriRedacted)
		return 0
	}

	cidrStr := rule.IP
	isNeg := strings.Index(cidrStr, "!") == 0
	hasSlash := strings.Contains(cidrStr, "/")
	if isNeg {
		cidrStr = cidrStr[1:]
	}
	if !hasSlash {
		ipAddr := net.ParseIP(cidrStr)
		if ipAddr == nil {
			logging.Printf("ERROR", "doTLSBreak: SessionID:%d Source address %s is not an IP\n", ctx.SessionNo, cidrStr)
			return 0
		}
		if ipAddr.To4() != nil {
			cidrStr = cidrStr + "/32"
		} else {
			cidrStr = cidrStr + "/128"
		}
	}
	checkProxy = !(strings.ToUpper(rule.Client) == "CLIENT")
	checkClient = !(strings.ToUpper(rule.Client) == "PROXY")

	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		logging.Printf("ERROR", "doTLSBreak: SessionID:%d Could not parse cidr: %s\n", ctx.SessionNo, cidrStr)
		return 0
	}
	if forwardedIP != "" {
		fIP, _, err := net.SplitHostPort(forwardedIP)
		if err != nil {
			//			if errors.Is(err, net.ErrMissingPort) {
			if strings.Contains(err.Error(), "missing port in address") {
				fIP = forwardedIP
			} else {
				logging.Printf("ERROR", "doTLSBreak: SessionID:%d Could not convert forwarded ip %s: %v\n", ctx.SessionNo, forwardedIP, err)
			}
		}
		forwIP := net.ParseIP(fIP)
		matchForw = cidr.Contains(forwIP)
	}

	if connectionIP != "" {
		cIP, _, err := net.SplitHostPort(connectionIP)
		if err != nil {
			//			if errors.Is(err, net.ErrMissingPort) {
			if strings.Contains(err.Error(), "missing port in address") {
				cIP = connectionIP
			} else {
				logging.Printf("ERROR", "doTLSBreak: SessionID:%d Could not convert connection ip %s: %v\n", ctx.SessionNo, connectionIP, err)
			}
		}
		connIP := net.ParseIP(cIP)
		matchConn = cidr.Contains(connIP)
		logging.Printf("DEBUG", "doTLSBreak: SessionID:%d cidr: %s connIP: %s\n", ctx.SessionNo, cidrStr, cIP)
	}
	logging.Printf("DEBUG", "doTLSBreak: SessionID:%d Flags: checkClient/checkProxy/matchConn/matchForw: %t/%t/%t/%t\n", ctx.SessionNo, checkClient, checkProxy, matchConn, matchForw)
	if checkClient && matchConn || checkClient && matchForw {
		if isNeg {
			return -1
		}
		return 1
	}
	if checkProxy && matchConn {
		if isNeg {
			return -1
		}
		return 1
	}

	return 0
}

// OnAccept Accept callback.
func OnAccept(ctx *httpproxy.Context, w http.ResponseWriter, r *http.Request) bool {
	var err error
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	// Handle local request has path "/info"
	tM := httpproxy.CleanUntrustedString(ctx, "Method", r.Method)
	tP := httpproxy.CleanUntrustedString(ctx, "Path", r.URL.Path)
	if tM == "GET" && !r.URL.IsAbs() && tP == "/info" {
		_, _ = w.Write([]byte("This is myproxy."))
		return true
	}
	// Check client cert if TLS is enabled
	if r.TLS != nil {
		if len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			tC := httpproxy.CleanUntrustedString(ctx, "Client cert CommonName", clientCert.Subject.CommonName)
			logging.Printf("DEBUG", "OnAccept: SessionID:%d Hello, Common Name: %s\n", ctx.SessionNo, tC)
		} else {
			logging.Printf("DEBUG", "OnAccept: SessionID:%d No client certificate provided\n", ctx.SessionNo)
		}
	}
	tU := httpproxy.CleanUntrustedString(ctx, "URL Redacted", r.URL.Redacted())
	logging.Printf("INFO", "OnAccept: SessionID:%d Process URL: %s\n", ctx.SessionNo, tU)
	setTLSBreak(ctx)
	setReadTimeout(ctx)
	tU = httpproxy.CleanUntrustedString(ctx, "URL String", ctx.Req.URL.String())
	proxyURL, err := upstream.GetProxy(ctx, tU)
	if err != nil {
		logging.Printf("ERROR", "OnAccept: SessionID:%d Failed to set upstream proxy: %v\n", ctx.SessionNo, err)
	}
	upstream.SetProxy(ctx, proxyURL)
	return false
}

// OnAuth Auth callback.
func OnAuth(ctx *httpproxy.Context, _ string, user string, pass string) bool {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	// Auth test user.
	if pass != "" {
		hash := sha256.New()
		hash.Write([]byte(pass))
		hashSum := string(hash.Sum(nil))
		hexSum := fmt.Sprintf("%x", hashSum)
		logging.Printf("DEBUG", "OnAuth: SessionID:%d User: %s Password hash: %s\n", ctx.SessionNo, user, hexSum)
		if user == readconfig.Config.Proxy.LocalBasicUser && hexSum == readconfig.Config.Proxy.LocalBasicHash {
			return true
		}
	}
	return false
}

// OnConnect Connect callback.
func OnConnect(ctx *httpproxy.Context, host string) (
	ConnectAction httpproxy.ConnectAction, newHost string) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	if ctx.TLSBreak {
		return httpproxy.ConnectMitm, host
	}
	return httpproxy.ConnectProxy, host

	// Apply "Man in the Middle" to all ssl connections. Never change host.
	//return httpproxy.ConnectMitm, host
}

// OnRequest Request callback.
func OnRequest(ctx *httpproxy.Context, _ *http.Request) (
	resp *http.Response) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	// var err error
	return
}

// OnResponse Response callback.
func OnResponse(ctx *httpproxy.Context, req *http.Request,
	resp *http.Response) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	if resp.StatusCode == http.StatusProxyAuthRequired {
		_, err := io.ReadAll(resp.Body)
		if err != nil {
			logging.Printf("ERROR", "OnResponse: SessionID:%d Could not read response body from response: %v\n", ctx.SessionNo, err)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		authenticate.DoProxyAuth(ctx, req, resp)
	}
	// Add header "Via: go-httpproxy".
	resp.Header.Add("Via", "myproxy")
}

func setReadTimeout(ctx *httpproxy.Context) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var connectionIP string = ctx.AccessLog.SourceIP
	var forwardedIP string = ctx.AccessLog.ForwardedIP
	var uri string = httpproxy.CleanUntrustedString(ctx, "URL Redacted", ctx.Req.URL.Redacted())
	var matchConn = false
	var matchForw = false
	var checkClient = true
	var checkProxy = true
	var incExcRex string
	var timeOut int

	if readconfig.Config.Websocket.Timeout != 0 {
		timeOut = readconfig.Config.Websocket.Timeout
	} else {
		if readconfig.Config.Connection.ReadTimeout != 0 {
			timeOut = readconfig.Config.Connection.ReadTimeout
		} else {
			timeOut = 0
		}
	}
	ctx.ReadTimeout = timeOut

	readconfig.Config.Websocket.Mu.Lock()
	defer readconfig.Config.Websocket.Mu.Unlock()
	for _, rule := range readconfig.Config.Websocket.Rules {
		// IncExc string format (!|)src,(client|proxy);regex,timeout
		logging.Printf("DEBUG", "setReadTimeout: SessionID:%d Check against Rules entry: %s,%s,%s,%d\n", ctx.SessionNo, rule.IP, rule.Client, rule.Regex, rule.Timeout)
		// Skip empty or whitespace-only rules
		if strings.TrimSpace(rule.IP) == "" {
			continue
		}
		timeOut = rule.Timeout
		// Match URL against regex
		matchURI, err := regexp.MatchString(rule.Regex, uri)
		if err != nil {
			logging.Printf("ERROR", "setReadTimeout: SessionID:%d Invalid regex: %s err: %v\n", ctx.SessionNo, incExcRex, err)
			continue
		}
		if !matchURI {
			logging.Printf("DEBUG", "setReadTimeout: SessionID:%d Regex does not match URI. regex: %s URI: %s\n", ctx.SessionNo, incExcRex, uri)
			continue
		}

		cidrStr := rule.IP
		isNeg := strings.Index(cidrStr, "!") == 0
		hasSlash := strings.Contains(cidrStr, "/")
		if isNeg {
			cidrStr = rule.IP[1:]
		}
		if !hasSlash {
			ipAddr := net.ParseIP(cidrStr)
			if ipAddr == nil {
				logging.Printf("ERROR", "setReadTimeout: SessionID:%d Source address %s is not an IP\n", ctx.SessionNo, cidrStr)
				continue
			}
			if ipAddr.To4() != nil {
				cidrStr = cidrStr + "/32"
			} else {
				cidrStr = cidrStr + "/128"
			}
		}
		checkProxy = !(strings.ToUpper(rule.Client) == "CLIENT")
		checkClient = !(strings.ToUpper(rule.Client) == "PROXY")

		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			logging.Printf("ERROR", "setReadTimeout: SessionID:%d Could not parse cidr: %s\n", ctx.SessionNo, cidrStr)
			continue
		}
		if forwardedIP != "" {
			fIP, _, err := net.SplitHostPort(forwardedIP)
			if err != nil {
				logging.Printf("ERROR", "setReadTimeout: SessionID:%d Could not convert forwarded ip %s: %v\n", ctx.SessionNo, forwardedIP, err)
			}
			forwIP := net.ParseIP(fIP)
			matchForw = cidr.Contains(forwIP)
		}

		if connectionIP != "" {
			cIP, _, err := net.SplitHostPort(connectionIP)
			if err != nil {
				logging.Printf("ERROR", "setReadTimeout: SessionID:%d Could not convert forwarded ip %s: %v\n", ctx.SessionNo, connectionIP, err)
			}
			connIP := net.ParseIP(cIP)
			matchConn = cidr.Contains(connIP)
		}
		logging.Printf("DEBUG", "setReadTimeout: SessionID:%d Flags: checkClient/checkProxy/matchConn/matchForw: %t/%t/%t/%t\n", ctx.SessionNo, checkClient, checkProxy, matchConn, matchForw)
		if checkClient && matchConn || checkClient && matchForw {
			if !isNeg {
				logging.Printf("DEBUG", "setReadTimeout: SessionID:%d Set timeout for %s: %d\n", ctx.SessionNo, uri, timeOut)
				ctx.ReadTimeout = timeOut
				return
			}
		}
		if checkProxy && matchConn {
			if !isNeg {
				logging.Printf("DEBUG", "setReadTimeout: SessionID:%d Set timeout for %s: %d\n", ctx.SessionNo, uri, timeOut)
				ctx.ReadTimeout = timeOut
				return
			}
		}
		if isNeg && !matchConn && !matchForw {
			logging.Printf("DEBUG", "setReadTimeout: SessionID:%d Set timeout for %s: %d\n", ctx.SessionNo, uri, timeOut)
			ctx.ReadTimeout = timeOut
			return
		}
		logging.Printf("DEBUG", "setReadTimeout: SessionID:%d cidr %s does not match IP %s\n", ctx.SessionNo, cidrStr, connectionIP)
	}
	logging.Printf("INFO", "setReadTimeout: SessionID:%d Set timeout for %s: %d\n", ctx.SessionNo, uri, ctx.ReadTimeout)
}

func runProxy(args []string) {
	var configFilename string
	var err error
	var caCert, caKey []byte
	var server *http.Server

	if len(args) == 0 {
		log.Printf("ERROR: runProxy: Missing argument list\n")
		os.Exit(1)
	}
	CommandLine := flag.NewFlagSet("runProxy", flag.ExitOnError)

	CommandLine.StringVar(&configFilename, "c", "myproxy.yaml", "Specify configuration filename.")

	err = CommandLine.Parse(args[1:])
	if err != nil {
		timeStamp := time.Now().Format(time.RFC1123)
		fmt.Printf("%s ERROR: runProxy: error parsing arguments: %v\n", timeStamp, err)
	}

	// Setup File watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		timeStamp := time.Now().Format(time.RFC1123)
		fmt.Printf("%s ERROR: runProxy: setting up file watcher, %v\n", timeStamp, err)
	}
	defer func() { _ = watcher.Close() }()

	// Read Yaml config file
	readconfig.Config, err = readconfig.ReadConfig(configFilename, watcher)
	if err != nil {
		timeStamp := time.Now().Format(time.RFC1123)
		fmt.Printf("%s ERROR: runProxy: configuration read error: %v\n", timeStamp, err)
		time.Sleep(2 * time.Second)
		os.Exit(1)
	}

	logging.Printf("INFO", "runProxy: Logging.Level: %s\n", readconfig.Config.Logging.Level)
	logging.Printf("INFO", "runProxy: Logging.Trace: %t\n", readconfig.Config.Logging.Trace)
	logging.Printf("INFO", "runProxy: Logging.File: %s\n", readconfig.Config.Logging.File)
	logging.Printf("INFO", "runProxy: Logging.AccessLog: %s\n", readconfig.Config.Logging.AccessLog)
	logging.Printf("INFO", "runProxy: PAC.Type: %s\n", readconfig.Config.PAC.Type)
	logging.Printf("INFO", "runProxy: PAC.URL: %s\n", readconfig.Config.PAC.URL)
	logging.Printf("INFO", "runProxy: PAC.File: %s\n", readconfig.Config.PAC.File)
	logging.Printf("INFO", "runProxy: PAC.Proxy: %s\n", readconfig.Config.PAC.Proxy)
	logging.Printf("INFO", "runProxy: Proxy.Authentication: %v\n", readconfig.Config.Proxy.Authentication)
	logging.Printf("INFO", "runProxy: Proxy.KRBDomain: %s\n", readconfig.Config.Proxy.KerberosDomain)
	logging.Printf("INFO", "runProxy: Proxy.KRBConfig: %s\n", readconfig.Config.Proxy.KerberosConfig)
	logging.Printf("INFO", "runProxy: Proxy.KRBCache: %s\n", readconfig.Config.Proxy.KerberosCache)
	logging.Printf("INFO", "runProxy: Proxy.KRBUser: %s\n", readconfig.Config.Proxy.KerberosUser)
	if readconfig.Config.Proxy.KerberosPass != "" {
		logging.Printf("INFO", "runProxy: Proxy.KRBPassword: ***\n")
	}
	logging.Printf("INFO", "runProxy: Proxy.NTLMDomain: %s\n", readconfig.Config.Proxy.NtlmDomain)
	logging.Printf("INFO", "runProxy: Proxy.NTLMUser: %s\n", readconfig.Config.Proxy.NtlmUser)
	if readconfig.Config.Proxy.NtlmPass != "" {
		logging.Printf("INFO", "runProxy: Proxy.NTLMPassword: ***\n")
	}
	logging.Printf("INFO", "runProxy: Proxy.BasicUser: %s\n", readconfig.Config.Proxy.BasicUser)
	if readconfig.Config.Proxy.BasicPass != "" {
		logging.Printf("INFO", "runProxy: Proxy.BasicPassword: ***\n")
	}
	logging.Printf("INFO", "runProxy: Proxy.LocalBasicUser: %s\n", readconfig.Config.Proxy.LocalBasicUser)
	logging.Printf("INFO", "runProxy: Proxy.LocalBasicHash: %s\n", readconfig.Config.Proxy.LocalBasicHash)

	if readconfig.Config.MITM.Enable {
		logging.Printf("INFO", "runProxy: MITM.TLSConfig.ServerCertfile: %s\n", readconfig.Config.MITM.TLSConfig.ServerCertfile)
		logging.Printf("INFO", "runProxy: MITM.TLSConfig.ServerKeyfile: %s\n", readconfig.Config.MITM.TLSConfig.ServerKeyfile)
		if readconfig.Config.MITM.TLSConfig.ServerCert != "" {
			logging.Printf("INFO", "runProxy: MITM certificate set\n")
			caCert = []byte(readconfig.Config.MITM.TLSConfig.ServerCert)
		}
		if readconfig.Config.MITM.TLSConfig.ServerKey != "" {
			logging.Printf("INFO", "runProxy: MITM key set\n")
			caKey = []byte(readconfig.Config.MITM.TLSConfig.ServerKey)
		}
	}

	var prx *httpproxy.Proxy
	if readconfig.Config.MITM.Enable {
		prx, err = httpproxy.NewProxyCert(caCert, caKey)
	} else {
		// Create a new proxy with default certificate pair.
		prx, err = httpproxy.NewProxy()
	}
	if err != nil {
		logging.Printf("ERROR", "runProxy: Error instantiating proxy: %v\n", err)
		return
	}

	// Set handlers.
	prx.OnError = OnError
	prx.OnAccept = OnAccept
	if readconfig.Config.Proxy.LocalBasicUser != "" {
		prx.OnAuth = OnAuth
	}
	prx.OnConnect = OnConnect
	prx.OnRequest = OnRequest
	prx.OnResponse = OnResponse

	prx.DoHProxyList = make(map[string]string)
	//prx.DoHdial = make(map[string]string)
	prx.DoHRt = make(map[string]http.RoundTripper)
	for _, r := range readconfig.Config.Connection.DNSServers {
		if strings.HasPrefix(r, "https://") {
			// Set context and add Prx DoH variables
			ctx := &httpproxy.Context{Prx: prx,
				SessionNo: 0,
			}
			proxyURL, err := upstream.GetProxy(ctx, r)
			if err != nil {
				logging.Printf("ERROR", "runProxy: Failed to set upstream proxy for DoH: %v\n", err)
			}
			upstream.SetProxy(ctx, proxyURL)
			prx.DoHProxyList[r] = proxyURL
			if proxyURL != "" {
				prx.DoHRt[r] = ctx.Rt
				ctx.Req, err = http.NewRequest("PUT", r, bytes.NewBuffer([]byte("")))
				if err != nil {
					logging.Printf("ERROR", "runProxy: Failed to set Request for DoH: %v\n", err)
					return
				}
				ctx.Req.Method = "CONNECT"
			}
		}
	}

	// Clamd connection
	if readconfig.Config.Clamd.Enable {
		logging.Printf("INFO", "runProxy: Clamd connection initalised to %s\n", readconfig.Config.Clamd.Connection)
		prx.ClamdStruct, err = viruscheck.SetupClamd(readconfig.Config.Clamd.Connection)
		if err != nil {
			logging.Printf("ERROR", "runProxy: SetupClamd error: %v\n", err)
			return
		}
	} else {
		logging.Printf("INFO", "runProxy: Clamd inspection not enabled\n")
		prx.ClamdStruct = nil
	}

	// Wireshark Listen...
	if readconfig.Config.Wireshark.Enable {
		logging.Printf("INFO", "runProxy: Wireshark listener listening on %s:%s !!!\n", readconfig.Config.Wireshark.IP, readconfig.Config.Wireshark.Port)
		listen := readconfig.Config.Wireshark.IP + ":" + readconfig.Config.Wireshark.Port
		err = protocol.ListenWireshark(listen)
		if err != nil {
			logging.Printf("ERROR", "runProxy: WiresharkListen error: %v\n", err)
			return
		}
	} else {
		logging.Printf("INFO", "runProxy: Wireshark inspection not enabled\n")
	}

	logging.Printf("INFO", "runProxy: Started version: %s\n", Version)
	// Listen...
	listen := readconfig.Config.Listen.IP + ":" + readconfig.Config.Listen.Port
	if readconfig.Config.Listen.TLS {
		logging.Printf("INFO", "runProxy: Enabling TLS\n")
		logging.Printf("INFO", "runProxy: Use certificate file: %s\n", readconfig.Config.Listen.TLSConfig.ServerCertfile)
		logging.Printf("INFO", "runProxy: Use key file: %s\n", readconfig.Config.Listen.TLSConfig.ServerKeyfile)
		logging.Printf("INFO", "runProxy: Use CA file: %s\n", readconfig.Config.Listen.TLSConfig.CAbundle)
		// #nosec G112 -- ReadHeaderTimeout is set immediatley below Server is called
		server = &http.Server{
			Addr:           listen,
			Handler:        prx,
			MaxHeaderBytes: 1 << 20, // 1Mb
			TLSConfig:      readconfig.Config.Listen.TLSConf,
		}
	} else {
		// #nosec G112 -- ReadHeaderTimeout is set immediatley below Server is called
		server = &http.Server{
			Addr:           listen,
			Handler:        prx,
			MaxHeaderBytes: 1 << 20, // 1Mb
		}
	}
	if readconfig.Config.Listen.ReadHeaderTimeout > 0 {
		server.ReadHeaderTimeout = time.Duration(readconfig.Config.Listen.ReadHeaderTimeout) * time.Second
		logging.Printf("INFO", "runProxy: Set proxy read header timeout to %d seconds\n", readconfig.Config.Listen.ReadHeaderTimeout)
	}
	if readconfig.Config.Listen.ReadTimeout > 0 {
		server.ReadTimeout = time.Duration(readconfig.Config.Listen.ReadTimeout) * time.Second
		logging.Printf("INFO", "runProxy: Set proxy read timeout to %d seconds\n", readconfig.Config.Listen.ReadTimeout)
	}
	if readconfig.Config.Listen.WriteTimeout > 0 {
		server.WriteTimeout = time.Duration(readconfig.Config.Listen.WriteTimeout) * time.Second
		logging.Printf("INFO", "runProxy: Set proxy write timeout to %d seconds\n", readconfig.Config.Listen.WriteTimeout)
	}
	if readconfig.Config.Listen.IdleTimeout > 0 {
		server.IdleTimeout = time.Duration(readconfig.Config.Listen.IdleTimeout) * time.Second
		logging.Printf("INFO", "runProxy: Set proxy idle timeout to %d seconds\n", readconfig.Config.Listen.IdleTimeout)
	}

	logging.Printf("INFO", "runProxy: Listening on %s:%s\n", readconfig.Config.Listen.IP, readconfig.Config.Listen.Port)
	if readconfig.Config.Listen.TLS {
		err = server.ListenAndServeTLS(readconfig.Config.Listen.TLSConfig.ServerCertfile, readconfig.Config.Listen.TLSConfig.ServerKeyfile)
	} else {
		err = server.ListenAndServe()
	}
	//err = http.ListenAndServe(listen, prx)
	if err != nil {
		logging.Printf("ERROR", "runProxy: ListenAndServer error: %v\n", err)
	}

}
