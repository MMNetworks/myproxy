package authenticate

import (
	"log"
	"net/http"
	"myproxy/http-proxy"
	"myproxy/readconfig"
	"regexp"
	"strings"
)

func DoProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) {
	var err error
	proxyAuthValues := resp.Header.Values("Proxy-Authenticate")
	log.Println("INFO: Proxy: DoProxyAuth: Test: Proxy-Authenticate header:", proxyAuthValues)
	// Get best match
	var bestAuth string = ""
	for _, v := range readconfig.Config.Proxy.Authentication {
		log.Printf("INFO: Proxy: DoProxyAuth: Test: Config: %s|%s\n", v, strings.Join(proxyAuthValues[:], ","))
		best, _ := regexp.MatchString(strings.ToUpper(v), strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
		if best {
			log.Printf("INFO: Proxy: DoProxyAuth: Match: %s\n", v)
			bestAuth = v
			break
		}
	}
	log.Printf("INFO: Proxy: DoProxyAuth: Best selected match: %s\n", bestAuth)
	ntlm, _ := regexp.MatchString("NTLM", strings.ToUpper(bestAuth))
	nego, _ := regexp.MatchString("NEGOTIATE", strings.ToUpper(bestAuth))
	basic, _ := regexp.MatchString("BASIC", strings.ToUpper(bestAuth))
	log.Printf("INFO: Proxy: DoProxyAuth: NTLM,Negotiate,Basic %v,%v,%v\n", ntlm, nego, basic)
	if ntlm {
		err = DoNTLMProxyAuth(ctx, req, resp, "NTLM")
		if err != nil {
			log.Printf("INFO: Proxy: DoProxyAuth: Match: %v\n", err)
		}

	} else if nego {
		err := DoNegotiateProxyAuth(ctx, req, resp)
		if err != nil {
			log.Printf("INFO: Proxy: DoProxyAuth: Match: %v\n", err)
		}
	} else if basic {
		err := DoBasicProxyAuth(ctx, req, resp)
		if err != nil {
			log.Printf("INFO: Proxy: DoProxyAuth: Match: %v\n", err)
		}
	} else {
	}
	log.Printf("INFO: Proxy: DoProxyAuth: Auth done\n")
	for k, v := range resp.Header {
		log.Printf("INFO: Proxy: DoProxyAuth: response header: %s=%s\n", k, v)
	}
}

func DoBasicProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	return nil
}
