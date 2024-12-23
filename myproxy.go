package main

import (
	"crypto/sha256"
	"flag"
	"io"
	"log"
	"myproxy/authenticate"
	"myproxy/http-proxy"
	"myproxy/readconfig"
	"myproxy/upstream"
	"net/http"
	// "github.com/yassinebenaid/godump"
)

func OnError(ctx *httpproxy.Context, where string,
	err *httpproxy.Error, opErr error) {
	// Log errors.
	log.Printf("ERR: %s: %s [%s]", where, err, opErr)
	// panic(err)
}

func OnAccept(ctx *httpproxy.Context, w http.ResponseWriter,
	r *http.Request) bool {
	// Handle local request has path "/info"
	log.Printf("INFO: Proxy: OnAccept: %s %s", ctx.Req.Method, ctx.Req.URL.String())
	if r.Method == "GET" && !r.URL.IsAbs() && r.URL.Path == "/info" {
		w.Write([]byte("This is go-httpproxy."))
		return true
	}
	upstream.SetProxy(ctx)
	return false
}

func OnAuth(ctx *httpproxy.Context, authType string, user string, pass string) bool {
	// Auth test user.
	log.Printf("INFO: Proxy: OnAuth: %s %s", ctx.Req.Method, ctx.Req.URL.String())
	if pass != "" {
		h := sha256.New()
		h.Write([]byte(pass))
		pbs := string(h.Sum(nil))
		if user == readconfig.Config.Proxy.LocalBasicUser && pbs == readconfig.Config.Proxy.LocalBasicHash {
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
	log.Printf("INFO: Proxy: OnConnect: %s %s", ctx.Req.Method, ctx.Req.URL.String())
	log.Printf("INFO: Proxy: OnConnect: Host:%s NewHost:%s", host, newHost)
	//      log.Printf("INFO: Proxy: Context: ")
	//      godump.Dump(ctx)
	return httpproxy.ConnectProxy, host
	//return httpproxy.ConnectMitm, host
}

func OnRequest(ctx *httpproxy.Context, req *http.Request) (
	resp *http.Response) {
	// var err error
	log.Printf("INFO: Proxy: OnRequest: %s %s", req.Method, req.URL.String())
	return
}

func OnResponse(ctx *httpproxy.Context, req *http.Request,
	resp *http.Response) {
	log.Printf("INFO: Proxy: OnResponse: %s %s", ctx.Req.Method, ctx.Req.URL.String())
	if resp.StatusCode == http.StatusProxyAuthRequired {
		_, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("INFO: Proxy: OnResponse: Could not read response body from response: %s", err)
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

	// flags declaration using flag package
	flag.StringVar(&configFilename, "c", "httpproxy.yaml", "Specify configuration filename. Default is httpproxy.yaml")

	flag.Parse() // after declaring flags we need to call it

	// Read Yaml config file
	readconfig.Config = readconfig.ReadConfig(configFilename)
	log.Printf("INFO: Proxy: main: PAC.Type: %s\n", readconfig.Config.PAC.Type)
	log.Printf("INFO: Proxy: main: PAC.URL: %s\n", readconfig.Config.PAC.URL)
	log.Printf("INFO: Proxy: main: PAC.File: %s\n", readconfig.Config.PAC.File)
	log.Printf("INFO: Proxy: main: PAC.Proxy: %s\n", readconfig.Config.PAC.Proxy)
	log.Printf("INFO: Proxy: main: Proxy.Authentication: %v\n", readconfig.Config.Proxy.Authentication)
	log.Printf("INFO: Proxy: main: Proxy.KRBDomain: %s\n", readconfig.Config.Proxy.KerberosDomain)
	log.Printf("INFO: Proxy: main: Proxy.KRBConfig: %s\n", readconfig.Config.Proxy.KerberosConfig)
	log.Printf("INFO: Proxy: main: Proxy.KRBCache: %s\n", readconfig.Config.Proxy.KerberosCache)
	log.Printf("INFO: Proxy: main: Proxy.KRBUser: %s\n", readconfig.Config.Proxy.KerberosUser)
	if readconfig.Config.Proxy.KerberosPass != "" {
		log.Printf("INFO: Proxy: main: Proxy.KRBPassword: ***\n")
	}
	log.Printf("INFO: Proxy: main: Proxy.NTLMDomain: %s\n", readconfig.Config.Proxy.NtlmDomain)
	log.Printf("INFO: Proxy: main: Proxy.NTLMUser: %s\n", readconfig.Config.Proxy.NtlmUser)
	if readconfig.Config.Proxy.NtlmPass != "" {
		log.Printf("INFO: Proxy: main: Proxy.NTLMPassword: ***\n")
	}
	log.Printf("INFO: Proxy: main: Proxy.BasicUser: %s\n", readconfig.Config.Proxy.BasicUser)
	if readconfig.Config.Proxy.BasicPass != "" {
		log.Printf("INFO: Proxy: main: Proxy.BasicPassword: ***\n")
	}
	log.Printf("INFO: Proxy: main: Proxy.LocalBasicUser: %s\n", readconfig.Config.Proxy.LocalBasicUser)
	log.Printf("INFO: Proxy: main: Proxy.LocalBasicHash: %s\n", readconfig.Config.Proxy.LocalBasicHash)

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
	http.ListenAndServe("127.0.0.1:9080", prx)
}
