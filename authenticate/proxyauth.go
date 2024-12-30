package authenticate

import (
	"encoding/base64"
	"fmt"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/readconfig"
	"net/http"
	"regexp"
	"strings"
)

func DoProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) {
	var err error
	proxyAuthValues := resp.Header.Values("Proxy-Authenticate")
	logging.Printf("DEBUG", "DoProxyAuth: Proxy-Authenticate header: %s\n", proxyAuthValues)
	// Get best match
	var bestAuth string = ""
	for _, v := range readconfig.Config.Proxy.Authentication {
		logging.Printf("DEBUG", "DoProxyAuth: determine preferred authentication method: %s|%s\n", v, strings.Join(proxyAuthValues[:], ","))
		best, _ := regexp.MatchString(strings.ToUpper(v), strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
		if best {
			logging.Printf("DEBUG", "DoProxyAuth: preferred method: %s\n", v)
			bestAuth = v
			break
		}
	}
	logging.Printf("DEBUG", "DoProxyAuth: selected authentication method: %s\n", bestAuth)
	ntlm, _ := regexp.MatchString("NTLM", strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
	nego, _ := regexp.MatchString("NEGOTIATE", strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
	basic, _ := regexp.MatchString("BASIC", strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
	logging.Printf("DEBUG", "DoProxyAuth: Other possible methods: NTLM,Negotiate,Basic %v,%v,%v\n", ntlm, nego, basic)
	ntlm, _ = regexp.MatchString("NTLM", strings.ToUpper(bestAuth))
	nego, _ = regexp.MatchString("NEGOTIATE", strings.ToUpper(bestAuth))
	basic, _ = regexp.MatchString("BASIC", strings.ToUpper(bestAuth))
	if ntlm {
		err = DoNTLMProxyAuth(ctx, req, resp, "NTLM")
		if err != nil {
			logging.Printf("DEBUG", "DoProxyAuth: NTLM failed: %v\n", err)
		}

	} else if nego {
		err := DoNegotiateProxyAuth(ctx, req, resp)
		if err != nil {
			logging.Printf("DEBUG", "DoProxyAuth: Negotiate failed: %v\n", err)
		}
	} else if basic {
		err := DoBasicProxyAuth(ctx, req, resp)
		if err != nil {
			logging.Printf("DEBUG", "DoProxyAuth: Basic failed: %v\n", err)
		}
	} else {
		logging.Printf("DEBUG", "DoProxyAuth: unknown authentication method: %s\n", bestAuth)
	}
	logging.Printf("DEBUG", "DoProxyAuth: Auth done\n")
	for k, v := range resp.Header {
		logging.Printf("DEBUG", "DoProxyAuth: response header: %s=%s\n", k, v)
	}
}

func DoBasicProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	var r = req
	var err error

	proxyUsername := readconfig.Config.Proxy.BasicUser
	proxyPassword := readconfig.Config.Proxy.BasicPass
	proxyAuth := proxyUsername + ":" + proxyPassword
	logging.Printf("DEBUG", "DoBasicProxyAuth: encoded string: %s\n", base64.StdEncoding.EncodeToString([]byte(proxyAuth)))

	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(proxyAuth))))
	basicResp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		logging.Printf("ERROR", "DoBasicroxyAuth: RoundTrip error(should not happen!): %v\n", err)
		if basicResp == nil {
			logging.Printf("ERROR", "DoBasicProxyAuth: no basicresp RoundTrip error: %v\n", err)
			return err
		} else if basicResp.StatusCode != http.StatusProxyAuthRequired {
			logging.Printf("ERROR", "DoBasicProxyAuth: RoundTrip error: %v\n", err)
			return err
		}
	}
	for k, v := range resp.Header {
		logging.Printf("DEBUG", "DoBasicProxyAuth: response header: %s=%s\n", k, v)
	}

	// Replace original response
	resp.StatusCode = basicResp.StatusCode
	resp.Status = basicResp.Status
	for k, _ := range resp.Header {
		resp.Header.Del(k)
		logging.Printf("DEBUG", "DoBasicProxyAuth: delete header %s\n", k)
	}
	for k, v := range basicResp.Header {
		for i := 0; i < len(v); i++ {
			resp.Header.Add(k, v[i])
		}
		logging.Printf("DEBUG", "DoBasicProxyAuth: add header %s=%s\n", k, v)
	}
	if basicResp.Body != http.NoBody {
		resp.Body = basicResp.Body
	} else {
		resp.Body = http.NoBody
	}
	resp.ContentLength = basicResp.ContentLength
	resp.TLS = basicResp.TLS
	copy(resp.TransferEncoding, basicResp.TransferEncoding)
	logging.Printf("DEBUG", "DoBasicProxyAuth: Auth done\n")
	return nil
}
