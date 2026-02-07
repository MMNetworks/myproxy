package service

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	"path/filepath"
	"regexp"
	"strings"
	"time"
	// "github.com/yassinebenaid/godump"
)

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
			logging.Printf("DEBUG", "setTLSBreak: SessionID:%d Check against rule entry: %s,%s,%s,%s\n", ctx.SessionNo, rule.IP, rule.Client, rule.Regex, rule.CertFile)
			isEmpty, _ := regexp.MatchString("^[ ]*$", rule.IP)
			if isEmpty {
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
	logging.Printf("INFO", "setTLSBreak: SessionID:%d TLS Break for URL %s: %s\n", ctx.SessionNo, ctx.Req.URL.Redacted(), status)
}

func doTLSBreak(ctx *httpproxy.Context, rule readconfig.MitmRule) int {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var connectionIP string = ctx.AccessLog.SourceIP
	var forwardedIP string = ctx.AccessLog.ForwardedIP
	var uri string = ctx.Req.URL.String()
	var uriRedacted string = ctx.Req.URL.Redacted()
	var matchConn bool = false
	var matchForw bool = false
	var checkClient bool = true
	var checkProxy bool = true
	var incExcRex string
	var rootCA string = ""

	// Parse Include/Exclude line

	rootCA = rule.CertFile

	if rootCA == "insecure" {
		// Replace the TLSClientConfig
		ctx.TLSConfig = &tls.Config{
			InsecureSkipVerify: true, // Skip certificate verification
		}
	} else {
		rootCAFilepath, err := filepath.Abs(rootCA)
		if err != nil {
			logging.Printf("ERROR", "doTLSBreak: SessionID:%d Could not read CA bundle: %v\n", ctx.SessionNo, err)
			return 0
		}

		caCerts, err := os.ReadFile(rootCAFilepath)
		if err != nil {
			logging.Printf("ERROR", "doTLSBreak: SessionID:%d Could  not read CA bundle: %v\n", ctx.SessionNo, err)
			return 0
		}

		customPool, err := x509.SystemCertPool()
		if err != nil {
			logging.Printf("ERROR", "doTLSBreak: SessionID:%d Failed to load system CA bundle: %v\n", ctx.SessionNo, err)
			return 0
		}

		ok := customPool.AppendCertsFromPEM(caCerts)
		if !ok {
			logging.Printf("ERROR", "doTLSBreak: SessionID:%d Failed to append custom CA bundle\n", ctx.SessionNo)
			return 0
		}

		// Replace the TLSClientConfig
		ctx.TLSConfig = &tls.Config{
			RootCAs: customPool,
		}
	}

	// Match URL against regex
	matchURI, err := regexp.MatchString(rule.Regex, uri)
	if err != nil {
		logging.Printf("ERROR", "doTLSBreak: SessionID:%d Invalid regex: %s error: %v\n", ctx.SessionNo, incExcRex, err)
		return 0
	}
	if !matchURI {
		logging.Printf("DEBUG", "doTLSBreak: SessionID:%d regex does not match. regex: %s URI: %s\n", ctx.SessionNo, incExcRex, uriRedacted)
		return 0
	}

	cidrStr := rule.IP
	isNeg := strings.Index(cidrStr, "!") == 0
	hasSlash := strings.Index(cidrStr, "/") > -1
	if isNeg {
		cidrStr = cidrStr[1:]
	}
	if !hasSlash {
		ipAddr := net.ParseIP(cidrStr)
		if ipAddr == nil {
			logging.Printf("ERROR", "doTLSBreak: SessionID:%d source address %s is not an IP\n", ctx.SessionNo, cidrStr)
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

func OnAccept(ctx *httpproxy.Context, w http.ResponseWriter,
	r *http.Request) bool {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	// Handle local request has path "/info"
	if r.Method == "GET" && !r.URL.IsAbs() && r.URL.Path == "/info" {
		w.Write([]byte("This is myproxy."))
		return true
	}
	// Check client cert if TLS is enabled
	if r.TLS != nil {
		if len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			logging.Printf("DEBUG", "OnAccept: SessionID:%d Hello, Common Name: %s\n", ctx.SessionNo, clientCert.Subject.CommonName)
		} else {
			logging.Printf("DEBUG", "OnAccept: SessionID:%d No client certificate provided\n", ctx.SessionNo)
		}
	}
	logging.Printf("INFO", "OnAccept: SessionID:%d Process URL: %s\n", ctx.SessionNo, r.URL.Redacted())
	setTLSBreak(ctx)
	setReadTimeout(ctx)
	err := upstream.SetProxy(ctx)
	if err != nil {
		logging.Printf("ERROR", "OnAccept: SessionID:%d Failed to set upstream proxy: %v\n", ctx.SessionNo, err)
	}
	return false
}

func OnAuth(ctx *httpproxy.Context, authType string, user string, pass string) bool {
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
		} else {
			return false
		}
	}
	return false
}

func OnConnect(ctx *httpproxy.Context, host string) (
	ConnectAction httpproxy.ConnectAction, newHost string) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	if ctx.TLSBreak {
		return httpproxy.ConnectMitm, host
	} else {
		return httpproxy.ConnectProxy, host
	}
	//return httpproxy.ConnectProxy, host
	// Apply "Man in the Middle" to all ssl connections. Never change host.
	//return httpproxy.ConnectMitm, host
}

func OnRequest(ctx *httpproxy.Context, req *http.Request) (
	resp *http.Response) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	// var err error
	return
}

func OnResponse(ctx *httpproxy.Context, req *http.Request,
	resp *http.Response) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	if resp.StatusCode == http.StatusProxyAuthRequired {
		_, err := io.ReadAll(resp.Body)
		if err != nil {
			logging.Printf("ERROR", "OnResponse: SessionID:%d Could not read response body from response: %v\n", ctx.SessionNo, err)
			return
		}
		defer resp.Body.Close()
		authenticate.DoProxyAuth(ctx, req, resp)
	}
	// Add header "Via: go-httpproxy".
	resp.Header.Add("Via", "myproxy")
}

func setReadTimeout(ctx *httpproxy.Context) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var connectionIP string = ctx.AccessLog.SourceIP
	var forwardedIP string = ctx.AccessLog.ForwardedIP
	var uri string = ctx.Req.URL.Redacted()
	var matchConn bool = false
	var matchForw bool = false
	var checkClient bool = true
	var checkProxy bool = true
	var incExcRex string
	var timeOut int

	if readconfig.Config.WebSocket.Timeout != 0 {
		timeOut = readconfig.Config.WebSocket.Timeout
	} else {
		if readconfig.Config.Connection.ReadTimeout != 0 {
			timeOut = readconfig.Config.Connection.ReadTimeout
		} else {
			timeOut = 0
		}
	}

	readconfig.Config.WebSocket.Mu.Lock()
	defer readconfig.Config.WebSocket.Mu.Unlock()
	for _, rule := range readconfig.Config.WebSocket.Rules {
		// IncExc string format (!|)src,(client|proxy);regex,timeout
		logging.Printf("DEBUG", "setReadTimeout: SessionID:%d Check against Rules entry: %s,%s,%s,%d\n", ctx.SessionNo, rule.IP, rule.Client, rule.Regex, rule.Timeout)
		isEmpty, _ := regexp.MatchString("^[ ]*$", rule.IP)
		if isEmpty {
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
		hasSlash := strings.Index(cidrStr, "/") > -1
		if isNeg {
			cidrStr = rule.IP[1:]
		}
		if !hasSlash {
			ipAddr := net.ParseIP(cidrStr)
			if ipAddr == nil {
				logging.Printf("ERROR", "setReadTimeout: SessionID:%d source address %s is not an IP\n", ctx.SessionNo, cidrStr)
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
	return
}

func runProxy(args []string) {
	var configFilename string
	var err error
	var caCert, caKey []byte
	var server *http.Server

	if len(args) == 0 {
		log.Printf("ERROR", "runProxy: Missing argument list\n")
		os.Exit(1)
	}
	CommandLine := flag.NewFlagSet("runProxy", flag.ExitOnError)

	CommandLine.StringVar(&configFilename, "c", "myproxy.yaml", "Specify configuration filename.")

	CommandLine.Parse(args[1:])

	// Setup File watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		timeStamp := time.Now().Format(time.RFC1123)
		fmt.Printf("%s ERROR: runProxy: setting up file watcher, %v\n", timeStamp, err)
	}
	defer watcher.Close()

	// Read Yaml config file
	readconfig.Config, err = readconfig.ReadConfig(configFilename, watcher)
	if err != nil {
		timeStamp := time.Now().Format(time.RFC1123)
		fmt.Printf("%s ERROR: runProxy: configuration read error: %v\n", timeStamp, err)
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
		logging.Printf("INFO", "runProxy: MITM Certfile: %s\n", readconfig.Config.MITM.Certfile)
		logging.Printf("INFO", "runProxy: MITM Keyfile: %s\n", readconfig.Config.MITM.Keyfile)
		if readconfig.Config.MITM.Cert != "" {
			logging.Printf("INFO", "runProxy: MITM certificate set\n")
			caCert = []byte(readconfig.Config.MITM.Cert)
		}
		if readconfig.Config.MITM.Key != "" {
			logging.Printf("INFO", "runProxy: MITM key set\n")
			caKey = []byte(readconfig.Config.MITM.Key)
		}
	}

	// Create a new proxy with default certificate pair.
	var prx *httpproxy.Proxy
	if readconfig.Config.MITM.Enable {
		prx, err = httpproxy.NewProxyCert(caCert, caKey)
	} else {
		prx, err = httpproxy.NewProxy()
	}
	if err != nil {
		logging.Printf("ERROR", "runProxy: Error instantiating proxy: %v\n", err)
		return
	}

	//        prx.signer.Ca = &prx.Ca
	//        if caCert == nil {
	//                caCert = DefaultCaCert
	//        }
	//        if caKey == nil {
	//                caKey = DefaultCaKey
	//        }
	//        var err error
	//        prx.Ca, err = tls.X509KeyPair(caCert, caKey)
	//        if err != nil {
	//                return nil, err
	//        }

	// Set handlers.
	prx.OnError = OnError
	prx.OnAccept = OnAccept
	if readconfig.Config.Proxy.LocalBasicUser != "" {
		prx.OnAuth = OnAuth
	}
	prx.OnConnect = OnConnect
	prx.OnRequest = OnRequest
	prx.OnResponse = OnResponse

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
		var TLSConfig *tls.Config
		logging.Printf("INFO", "runProxy: Enabling TLS\n")
		logging.Printf("INFO", "runProxy: Use certificate file: %s\n", readconfig.Config.Listen.Certfile)
		logging.Printf("INFO", "runProxy: Use key file: %s\n", readconfig.Config.Listen.Keyfile)
		logging.Printf("INFO", "runProxy: Use CA file: %s\n", readconfig.Config.Listen.CAfile)
		// TLS config requiring client certs
		caCertPool := x509.NewCertPool()
		if readconfig.Config.Listen.CAfile != "insecure" {
			caCert, err := os.ReadFile(readconfig.Config.Listen.CAfile)
			if err != nil {
				logging.Printf("ERROR", "runProxy: Could  not read CA bundle %s: %v\n", readconfig.Config.Listen.CAfile, err)
				return
			}
			caCertPool.AppendCertsFromPEM(caCert)
			TLSConfig = &tls.Config{
				ClientCAs:  caCertPool,
				ClientAuth: tls.RequestClientCert, // request client cert
				//			ClientAuth: tls.RequireAndVerifyClientCert, // enforce client cert
			}
		} else {
			TLSConfig = &tls.Config{
				ClientCAs:          caCertPool,
				ClientAuth:         tls.RequestClientCert, // request client cert
				InsecureSkipVerify: true,                  // Skip certificate verification
				//			ClientAuth: tls.RequireAndVerifyClientCert, // enforce client cert
			}
		}
		server = &http.Server{
			Addr:           listen,
			Handler:        prx,
			MaxHeaderBytes: 1 << 20, // 1Mb
			TLSConfig:      TLSConfig,
		}
	} else {
		server = &http.Server{
			Addr:           listen,
			Handler:        prx,
			MaxHeaderBytes: 1 << 20, // 1Mb
		}
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
		err = server.ListenAndServeTLS(readconfig.Config.Listen.Certfile, readconfig.Config.Listen.Keyfile)
	} else {
		err = server.ListenAndServe()
	}
	//err = http.ListenAndServe(listen, prx)
	if err != nil {
		logging.Printf("ERROR", "runProxy: ListenAndServer error: %v\n", err)
	}

	return
}
