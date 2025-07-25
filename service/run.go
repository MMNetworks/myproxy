package service

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/gopacket/gopacket/pcapgo"
	"io"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/protocol"
	"myproxy/readconfig"
	"myproxy/upstream"
	"myproxy/upstream/authenticate"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	// "github.com/yassinebenaid/godump"
)

var pcapwChan = make(chan pcapgo.Writer)
var wiresharkAlive bool = false
var wiresharkWriter pcapgo.Writer

func OnError(ctx *httpproxy.Context, where string,
	err *httpproxy.Error, opErr error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	logging.Printf("ERROR", "OnError: SessionID:%d %s: %s [%s]\n", ctx.SessionNo, where, err, opErr)
	// panic(err)
}

func OnAccept(ctx *httpproxy.Context, w http.ResponseWriter,
	r *http.Request) bool {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	// Handle local request has path "/info"
	if r.Method == "GET" && !r.URL.IsAbs() && r.URL.Path == "/info" {
		w.Write([]byte("This is myproxy."))
		return true
	}
	err := upstream.SetProxy(ctx)
	if err != nil {
		logging.Printf("ERROR:", "OnAccept: SessionID:%d failed to set proxy: %v\n", ctx.SessionNo, err)
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

func doTLSBreak(ctx *httpproxy.Context, incExc string) int {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var connectionIP string = ctx.AccessLog.SourceIP
	var forwardedIP string = ctx.AccessLog.ForwardedIP
	var uri string = ctx.ConnectReq.URL.String()
	var matchConn bool = false
	var matchForw bool = false
	var checkClient bool = true
	var checkProxy bool = true

	// Parse Include/Exclude line
	spos := strings.Index(incExc, ";")
	cidrStr := incExc[:spos]
	spos2 := strings.Index(incExc[spos+1:], ";")
	clientOrProxyStr := incExc[spos+1 : spos+spos2+1]
	incExcRex := incExc[spos+spos2+2:]

	// Match URL against regex
	matchURI, err := regexp.MatchString(incExcRex, uri)
	if err != nil {
		logging.Printf("DEBUG", "doTLSBreak: sessionID:%d Invalid regex: %s err: %v\n", ctx.SessionNo, incExcRex, err)
		return 0
	}
	if !matchURI {
		logging.Printf("DEBUG", "doTLSBreak: sessionID:%d regex does not match. regex: %s URI: %s\n", ctx.SessionNo, incExcRex, uri)
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
		logging.Printf("DEBUG", "doTLSBreak: SessionID:%d cn not parse cidr: %s\n", ctx.SessionNo, cidrStr)
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
	logging.Printf("DEBUG", "doTLSBreak: SessionID:%d checkClient: %t\n", ctx.SessionNo, checkClient)
	logging.Printf("DEBUG", "doTLSBreak: SessionID:%d checkProxy: %t\n", ctx.SessionNo, checkProxy)
	logging.Printf("DEBUG", "doTLSBreak: SessionID:%d matchConn: %t\n", ctx.SessionNo, matchConn)
	logging.Printf("DEBUG", "doTLSBreak: SessionID:%d matchForw: %t\n", ctx.SessionNo, matchForw)
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

func OnConnect(ctx *httpproxy.Context, host string) (
	ConnectAction httpproxy.ConnectAction, newHost string) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var breakTLS bool = false
	if readconfig.Config.MITM.Enable {
		if len(readconfig.Config.MITM.IncExc) == 0 {
			// Empty Include/Exclude list => TLS breal all
			breakTLS = true
		}
		for _, v := range readconfig.Config.MITM.IncExc {
			// IncExc string format (!|)src,(client|proxy);regex
			logging.Printf("DEBUG", "OnConnect: SessionID:%d IncExc: %s\n", ctx.SessionNo, v)
			isEmpty, _ := regexp.MatchString("^[ ]*$", v)
			if isEmpty {
				continue
			}
			tlsBreak := doTLSBreak(ctx, v)
			if tlsBreak < 0 {
				breakTLS = false
				break
			} else if tlsBreak > 0 {
				breakTLS = true
				break
			}
		}
		logging.Printf("DEBUG", "OnConnect: SessionID:%d URL: %s MITM:%t\n", ctx.SessionNo, ctx.ConnectReq.URL.String(), breakTLS)
		if breakTLS {
			return httpproxy.ConnectMitm, host
		} else {
			return httpproxy.ConnectProxy, host
		}
	} else {
		logging.Printf("DEBUG", "OnConnect: SessionID:%d URL: %s MITM:%t\n", ctx.SessionNo, ctx.ConnectReq.URL.String(), false)
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

	requestDump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		logging.Printf("ERROR", "%s: SessionID:%d request dump failed: %v\n", logging.GetFunctionName(), ctx.SessionNo, err)
		return
	}
	dst := ctx.AccessLog.DestinationIP
	if dst == "" {
		dst = ctx.AccessLog.ProxyIP
	}
	src := ctx.AccessLog.SourceIP
	err = protocol.WriteWireshark(src, dst, requestDump)
	if err != nil {
		logging.Printf("ERROR", "OnRequest: SessionID:%d Could not write to Wireshark: %v\n", ctx.SessionNo, err)
		wiresharkAlive = false
	}
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

	responseDump, err := httputil.DumpResponse(resp, true)
	dst := ctx.AccessLog.DestinationIP
	if dst == "" {
		dst = ctx.AccessLog.ProxyIP
	}
	src := ctx.AccessLog.SourceIP
	err = protocol.WriteWireshark(dst, src, responseDump)
	if err != nil {
		logging.Printf("ERROR", "OnResponse: SessionID:%d Could not write to Wireshark: %v\n", ctx.SessionNo, err)
		wiresharkAlive = false
	}
}

func runProxy(args []string) {
	var configFilename string
	var err error
	var caCert, caKey []byte

	if len(args) == 0 {
		logging.Printf("ERROR", "runProxy: missing argument list\n")
		os.Exit(1)
	}
	CommandLine := flag.NewFlagSet("runProxy", flag.ExitOnError)

	CommandLine.StringVar(&configFilename, "c", "myproxy.yaml", "Specify configuration filename.")

	CommandLine.Parse(args[1:])

	// Read Yaml config file
	readconfig.Config, err = readconfig.ReadConfig(configFilename)
	if err != nil {
		logging.Printf("ERROR", "runProxy: config read error: %v\n", err)
		return
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
		logging.Printf("ERROR", "runProxy: error instantiating proxy %v\n", err)
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

	// Wireshark Listen...
	if readconfig.Config.Wireshark.IP != "" {
		logging.Printf("INFO", "runProxy: Wireshark listener listening on %s:%s !!!\n", readconfig.Config.Wireshark.IP, readconfig.Config.Wireshark.Port)
		listen := readconfig.Config.Wireshark.IP + ":" + readconfig.Config.Wireshark.Port
		err = protocol.ListenWireshark(listen)
		if err != nil {
			logging.Printf("ERROR", "runProxy: WiresharkListen error: %v\n", err)
			return
		}
	}

	// Listen...
	logging.Printf("DEBUG", "runProxy: Listening on %s:%s\n", readconfig.Config.Listen.IP, readconfig.Config.Listen.Port)
	listen := readconfig.Config.Listen.IP + ":" + readconfig.Config.Listen.Port
	err = http.ListenAndServe(listen, prx)
	if err != nil {
		logging.Printf("ERROR", "runProxy: ListenAndServer error: %v\n", err)
	}

	return
}
