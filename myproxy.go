package main

import (
	"crypto/sha256"
	"flag"
	"io"
	"log"
	"fmt"
	"os"
	"myproxy/authenticate"
	"myproxy/http-proxy"
	"myproxy/readconfig"
	"myproxy/upstream"
	"myproxy/logging"
	"net/http"
	// "github.com/yassinebenaid/godump"
)

func OnError(ctx *httpproxy.Context, where string,
	err *httpproxy.Error, opErr error) {
	// Log errors.
	logging.Printf("ERROR","OnError: %s: %s [%s]\n", where, err, opErr)
	// panic(err)
}

func OnAccept(ctx *httpproxy.Context, w http.ResponseWriter,
	r *http.Request) bool {
	// Handle local request has path "/info"
	logging.Printf("DEBUG","OnAccept: %s %s\n", ctx.Req.Method, ctx.Req.URL.String())
	if r.Method == "GET" && !r.URL.IsAbs() && r.URL.Path == "/info" {
		w.Write([]byte("This is go-httpproxy."))
		return true
	}
	err := upstream.SetProxy(ctx)
	if err != nil {
		logging.Printf("ERROR:","OnAccpet: failed to set proxy: %v\n",err)
	}
	return false
}

func OnAuth(ctx *httpproxy.Context, authType string, user string, pass string) bool {
	// Auth test user.
	logging.Printf("DEBUG","OnAuth: %s %s\n", ctx.Req.Method, ctx.Req.URL.String())
	if pass != "" {
		hash := sha256.New()
		hash.Write([]byte(pass))
		hashSum := string(hash.Sum(nil))
		hexSum := fmt.Sprintf("%x",hashSum)
		logging.Printf("DEBUG","OnAuth: User: %s Password hash: %s\n", user,hexSum)
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
	// Apply "Man in the Middle" to all ssl connections. Never change host.
	logging.Printf("DEBUG","OnConnect: %s %s\n", ctx.Req.Method, ctx.Req.URL.String())
	logging.Printf("DEBUG","OnConnect: Host:%s NewHost:%s\n", host, newHost)
	//      log.Printf("INFO: Proxy: Context: ")
	//      godump.Dump(ctx)
	return httpproxy.ConnectProxy, host
	//return httpproxy.ConnectMitm, host
}

func OnRequest(ctx *httpproxy.Context, req *http.Request) (
	resp *http.Response) {
	// var err error
	logging.Printf("DEBUG","OnRequest: %s %s\n", req.Method, req.URL.String())
	return
}

func OnResponse(ctx *httpproxy.Context, req *http.Request,
	resp *http.Response) {
	logging.Printf("DEBUG","OnResponse: %s %s\n", ctx.Req.Method, ctx.Req.URL.String())
	if resp.StatusCode == http.StatusProxyAuthRequired {
		_, err := io.ReadAll(resp.Body)
		if err != nil {
			logging.Printf("ERROR","OnResponse: Could not read response body from response: %v\n", err)
			return
		}
		defer resp.Body.Close()
		authenticate.DoProxyAuth(ctx, req, resp)
	}
	// Add header "Via: go-httpproxy".
	resp.Header.Add("Via", "go-httpproxy")
}

func main() {
	// variables declaration
	var configFilename string
	var err error

	// flags declaration using flag package
	flag.StringVar(&configFilename, "c", "myproxy.yaml", "Specify configuration filename. Default is myproxy.yaml")

	flag.Parse() // after declaring flags we need to call it

	// Read Yaml config file
	readconfig.Config ,err = readconfig.ReadConfig(configFilename)
	if err != nil {
		log.Printf("ERROR: Main: config read error: %s\n", configFilename)
		os.Exit(1)
	}
	logging.Printf("INFO","Main: Logging.Level: %s\n", readconfig.Config.Logging.Level)
	logging.Printf("INFO","Main: Logging.File: %s\n", readconfig.Config.Logging.File)
	logging.Printf("INFO","Main: PAC.Type: %s\n", readconfig.Config.PAC.Type)
	logging.Printf("INFO","Main: PAC.URL: %s\n", readconfig.Config.PAC.URL)
	logging.Printf("INFO","Main: PAC.File: %s\n", readconfig.Config.PAC.File)
	logging.Printf("INFO","Main: PAC.Proxy: %s\n", readconfig.Config.PAC.Proxy)
	logging.Printf("INFO","Main: Proxy.Authentication: %v\n", readconfig.Config.Proxy.Authentication)
	logging.Printf("INFO","Main: Proxy.KRBDomain: %s\n", readconfig.Config.Proxy.KerberosDomain)
	logging.Printf("INFO","Main: Proxy.KRBConfig: %s\n", readconfig.Config.Proxy.KerberosConfig)
	logging.Printf("INFO","Main: Proxy.KRBCache: %s\n", readconfig.Config.Proxy.KerberosCache)
	logging.Printf("INFO","Main: Proxy.KRBUser: %s\n", readconfig.Config.Proxy.KerberosUser)
	if readconfig.Config.Proxy.KerberosPass != "" {
		logging.Printf("INFO","Main: Proxy.KRBPassword: ***\n")
	}
	logging.Printf("INFO","Main: Proxy.NTLMDomain: %s\n", readconfig.Config.Proxy.NtlmDomain)
	logging.Printf("INFO","Main: Proxy.NTLMUser: %s\n", readconfig.Config.Proxy.NtlmUser)
	if readconfig.Config.Proxy.NtlmPass != "" {
		logging.Printf("INFO","Main: Proxy.NTLMPassword: ***\n")
	}
	logging.Printf("INFO","Main: Proxy.BasicUser: %s\n", readconfig.Config.Proxy.BasicUser)
	if readconfig.Config.Proxy.BasicPass != "" {
		logging.Printf("INFO","Main: Proxy.BasicPassword: ***\n")
	}
	logging.Printf("INFO","Main: Proxy.LocalBasicUser: %s\n", readconfig.Config.Proxy.LocalBasicUser)
	logging.Printf("INFO","Main: Proxy.LocalBasicHash: %s\n", readconfig.Config.Proxy.LocalBasicHash)

	// Create a new proxy with default certificate pair.
	prx, _ := httpproxy.NewProxy()

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

	// Listen...
	logging.Printf("DEBUG","Main: Listening on %s:%s\n", readconfig.Config.Listen.IP, readconfig.Config.Listen.Port)
	listen := readconfig.Config.Listen.IP + ":" +  readconfig.Config.Listen.Port
	http.ListenAndServe(listen, prx)
}
