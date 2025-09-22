package service

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
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
	"strconv"
	"strings"
	"time"
	// "github.com/yassinebenaid/godump"
)

func OnError(ctx *httpproxy.Context, where string,
	err *httpproxy.Error, opErr error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	logging.Printf("ERROR", "OnError: SessionID:%d %s: %s [%s]\n", ctx.SessionNo, where, err, opErr)
	// panic(err)
}

func setTLSBreak(ctx *httpproxy.Context) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	if readconfig.Config.MITM.Enable {
		if len(readconfig.Config.MITM.IncExc) == 0 {
			// Empty Include/Exclude list => TLS break all
			ctx.TLSBreak = true
		}
		for _, v := range readconfig.Config.MITM.IncExc {
			// IncExc string format (!|)src,(client|proxy);regex,rootCA
			logging.Printf("DEBUG", "setTLSBreak: SessionID:%d Check against IncExc entry: %s\n", ctx.SessionNo, v)
			isEmpty, _ := regexp.MatchString("^[ ]*$", v)
			if isEmpty {
				continue
			}
			tlsBreak := doTLSBreak(ctx, v)
			if tlsBreak < 0 {
				ctx.TLSBreak = false
				break
			} else if tlsBreak > 0 {
				ctx.TLSBreak = true
				break
			}
		}
	}
	var status string
	if ctx.TLSBreak {
		status = "enabled"
	} else {
		status = "disabled"
	}
	logging.Printf("INFO", "setTLSBreak: SessionID:%d TLS Break for URL %s: %s\n", ctx.SessionNo, ctx.Req.URL.Redacted(), status)
}

func doTLSBreak(ctx *httpproxy.Context, incExc string) int {
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
	spos := strings.Index(incExc, ";")
	cidrStr := incExc[:spos]
	spos2 := strings.Index(incExc[spos+1:], ";")
	clientOrProxyStr := incExc[spos+1 : spos+spos2+1]
	spos3 := strings.Index(incExc[spos+spos2+2:], ";")
	if spos3 >= 0 {

		incExcRex = incExc[spos+spos2+2 : spos+spos2+spos3+2]
		rootCA = incExc[spos+spos2+spos3+3:]

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
	} else {
		incExcRex = incExc[spos+spos2+2:]
	}

	// Match URL against regex
	matchURI, err := regexp.MatchString(incExcRex, uri)
	if err != nil {
		logging.Printf("ERROR", "doTLSBreak: SessionID:%d Invalid regex: %s error: %v\n", ctx.SessionNo, incExcRex, err)
		return 0
	}
	if !matchURI {
		logging.Printf("DEBUG", "doTLSBreak: SessionID:%d regex does not match. regex: %s URI: %s\n", ctx.SessionNo, incExcRex, uriRedacted)
		return 0
	}

	isNeg := strings.Index(cidrStr, "!") == 0
	hasSlash := strings.Index(cidrStr, "/") > -1
	if isNeg {
		cidrStr = cidrStr[1:]
	}
	if !hasSlash {
		cidrStr = cidrStr + "/32"
	}
	checkProxy = !(strings.ToUpper(clientOrProxyStr) == "CLIENT")
	checkClient = !(strings.ToUpper(clientOrProxyStr) == "PROXY")

	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		logging.Printf("ERROR", "doTLSBreak: SessionID:%d Could not parse cidr: %s\n", ctx.SessionNo, cidrStr)
		return 0
	}
	if forwardedIP != "" {
		cpos := strings.Index(forwardedIP, ":")
		if cpos != -1 {
			forwardedIP = forwardedIP[:cpos]
		}
		forwIP := net.ParseIP(forwardedIP)
		matchForw = cidr.Contains(forwIP)
	}

	if connectionIP != "" {
		cpos := strings.Index(connectionIP, ":")
		if cpos != -1 {
			connectionIP = connectionIP[:cpos]
		}
		connIP := net.ParseIP(connectionIP)
		matchConn = cidr.Contains(connIP)
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
	var err error
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

	for _, incExc := range readconfig.Config.WebSocket.IncExc {
		// IncExc string format (!|)src,(client|proxy);regex,rootCA
		logging.Printf("DEBUG", "setReadTimeout: SessionID:%d Check against IncExc entry: %s\n", ctx.SessionNo, incExc)
		isEmpty, _ := regexp.MatchString("^[ ]*$", incExc)
		if isEmpty {
			continue
		}
		// Parse Include/Exclude line
		spos := strings.Index(incExc, ";")
		cidrStr := incExc[:spos]
		spos2 := strings.Index(incExc[spos+1:], ";")
		clientOrProxyStr := incExc[spos+1 : spos+spos2+1]
		spos3 := strings.Index(incExc[spos+spos2+2:], ";")
		if spos3 >= 0 {
			incExcRex = incExc[spos+spos2+2 : spos+spos2+spos3+2]
			if spos+spos2+spos3+3 < len(incExc) {
				timeOut, err = strconv.Atoi(incExc[spos+spos2+spos3+3:])
				if err != nil {
					logging.Printf("ERROR", "setReadTimeout: SessionID:%d Error converting string %s to int: %v\n", ctx.SessionNo, incExc[spos+spos2+spos3+3:], err)
				}
			}
		} else {
			incExcRex = incExc[spos+spos2+2:]
		}

		// Match URL against regex
		matchURI, err := regexp.MatchString(incExcRex, uri)
		if err != nil {
			logging.Printf("ERROR", "setReadTimeout: SessionID:%d Invalid regex: %s err: %v\n", ctx.SessionNo, incExcRex, err)
			continue
		}
		if !matchURI {
			logging.Printf("DEBUG", "setReadTimeout: SessionID:%d Regex does not match URI. regex: %s URI: %s\n", ctx.SessionNo, incExcRex, uri)
			continue
		}

		isNeg := strings.Index(cidrStr, "!") == 0
		hasSlash := strings.Index(cidrStr, "/") > -1
		if isNeg {
			cidrStr = cidrStr[1:]
		}
		if !hasSlash {
			cidrStr = cidrStr + "/32"
		}
		checkProxy = !(strings.ToUpper(clientOrProxyStr) == "CLIENT")
		checkClient = !(strings.ToUpper(clientOrProxyStr) == "PROXY")

		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			logging.Printf("ERROR", "setReadTimeout: SessionID:%d Could not parse cidr: %s\n", ctx.SessionNo, cidrStr)
			continue
		}
		if forwardedIP != "" {
			cpos := strings.Index(forwardedIP, ":")
			if cpos != -1 {
				forwardedIP = forwardedIP[:cpos]
			}
			forwIP := net.ParseIP(forwardedIP)
			matchForw = cidr.Contains(forwIP)
		}

		if connectionIP != "" {
			cpos := strings.Index(connectionIP, ":")
			if cpos != -1 {
				connectionIP = connectionIP[:cpos]
			}
			connIP := net.ParseIP(connectionIP)
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
		logging.Printf("DEBUG", "setReadTimeout: SessionID:%d cidr %s does not match IP %s\n", ctx.SessionNo, cidrStr, connectionIP)
	}
	logging.Printf("INFO", "setReadTimeout: SessionID:%d Set timeout for %s: %d\n", ctx.SessionNo, uri, ctx.ReadTimeout)
	return
}

func runProxy(args []string) {
	var configFilename string
	var err error
	var caCert, caKey []byte

	if len(args) == 0 {
		log.Printf("ERROR", "runProxy: Missing argument list\n")
		os.Exit(1)
	}
	CommandLine := flag.NewFlagSet("runProxy", flag.ExitOnError)

	CommandLine.StringVar(&configFilename, "c", "myproxy.yaml", "Specify configuration filename.")

	CommandLine.Parse(args[1:])

	// Read Yaml config file
	readconfig.Config, err = readconfig.ReadConfig(configFilename)
	if err != nil {
		timeStamp := time.Now().Format(time.RFC1123)
		fmt.Printf("%s ERROR: runProxy: configuration read error: %v\n", timeStamp, err)
		// Allow logging go routine time to log it ;-)
		return
	}

	go logging.Processor()

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
		logging.Printf("INFO", "runProxy: Certfile: %s\n", readconfig.Config.MITM.Certfile)
		logging.Printf("INFO", "runProxy: Keyfile: %s\n", readconfig.Config.MITM.Keyfile)
		if readconfig.Config.MITM.Cert != "" {
			logging.Printf("INFO", "runProxy: Cert set\n")
			caCert = []byte(readconfig.Config.MITM.Cert)
		}
		if readconfig.Config.MITM.Key != "" {
			logging.Printf("INFO", "runProxy: Key set\n")
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
	logging.Printf("INFO", "runProxy: Listening on %s:%s\n", readconfig.Config.Listen.IP, readconfig.Config.Listen.Port)
	listen := readconfig.Config.Listen.IP + ":" + readconfig.Config.Listen.Port
	server := &http.Server{
		Addr:           listen,
		Handler:        prx,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1Mb
	}
	err = server.ListenAndServe()
	//err = http.ListenAndServe(listen, prx)
	if err != nil {
		logging.Printf("ERROR", "runProxy: ListenAndServer error: %v\n", err)
	}

	return
}
