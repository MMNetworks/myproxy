package authenticate

import (
	"log"
	"net/http"
	"myproxy/http-proxy"
	"myproxy/readconfig"
        "myproxy/logging"
	"regexp"
	"strings"
)

func DoProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) {
	var err error
	proxyAuthValues := resp.Header.Values("Proxy-Authenticate")
	logging.Printf("DEBUG","DoProxyAuth: Proxy-Authenticate header: %s\n", proxyAuthValues)
	// Get best match
	var bestAuth string = ""
	for _, v := range readconfig.Config.Proxy.Authentication {
		logging.Printf("DEBUG","DoProxyAuth: determine preferred authentication method: %s|%s\n", v, strings.Join(proxyAuthValues[:], ","))
		best, _ := regexp.MatchString(strings.ToUpper(v), strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
		if best {
			logging.Printf("DEBUG","DoProxyAuth: preferred method: %s\n", v)
			bestAuth = v
			break
		}
	}
	logging.Printf("DEBUG","DoProxyAuth: selected authentication method: %s\n", bestAuth)
	ntlm, _ := regexp.MatchString("NTLM", strings.ToUpper(bestAuth))
	nego, _ := regexp.MatchString("NEGOTIATE", strings.ToUpper(bestAuth))
	basic, _ := regexp.MatchString("BASIC", strings.ToUpper(bestAuth))
	logging.Printf("DEBUG","DoProxyAuth: Other possible methods: NTLM,Negotiate,Basic %v,%v,%v\n", ntlm, nego, basic)
	if ntlm {
		err = DoNTLMProxyAuth(ctx, req, resp, "NTLM")
		if err != nil {
			logging.Printf("DEBUG","DoProxyAuth: NTLM failed: %v\n", err)
		}

	} else if nego {
		err := DoNegotiateProxyAuth(ctx, req, resp)
		if err != nil {
			logging.Printf("DEBUG","DoProxyAuth: Negotiate failed: %v\n", err)
		}
	} else if basic {
		err := DoBasicProxyAuth(ctx, req, resp)
		if err != nil {
			logging.Printf("DEBUG","DoProxyAuth: Basic failed: %v\n", err)
		}
	} else {
		logging.Printf("DEBUG","DoProxyAuth: unknown authentication method: %s\n",bestAuth )
	}
	logging.Printf("DEBUG","DoProxyAuth: Auth done\n")
	for k, v := range resp.Header {
		logging.Printf("DEBUG","DoProxyAuth: response header: %s=%s\n", k, v)
	}
}

func DoBasicProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	return nil
}
