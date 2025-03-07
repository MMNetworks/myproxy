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
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(),ctx.SessionNo)
	var err error
	proxyAuthValues := resp.Header.Values("Proxy-Authenticate")
	logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Proxy-Authenticate header: %s\n", ctx.SessionNo, proxyAuthValues)
	// Get best match
	var bestAuth string = ""
	for _, v := range readconfig.Config.Proxy.Authentication {
		logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d determine preferred authentication method: %s|%s\n", ctx.SessionNo, v, strings.Join(proxyAuthValues[:], ","))
		best, _ := regexp.MatchString(strings.ToUpper(v), strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
		if best {
			logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d preferred method: %s\n", ctx.SessionNo, v)
			bestAuth = v
			break
		}
	}
	logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d selected authentication method: %s\n", ctx.SessionNo, bestAuth)
	ntlm, _ := regexp.MatchString("NTLM", strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
	nego, _ := regexp.MatchString("NEGOTIATE", strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
	basic, _ := regexp.MatchString("BASIC", strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
	logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Other possible methods: NTLM,Negotiate,Basic %v,%v,%v\n", ctx.SessionNo, ntlm, nego, basic)
	ntlm, _ = regexp.MatchString("NTLM", strings.ToUpper(bestAuth))
	nego, _ = regexp.MatchString("NEGOTIATE", strings.ToUpper(bestAuth))
	basic, _ = regexp.MatchString("BASIC", strings.ToUpper(bestAuth))
	if ntlm {
		err = DoNTLMProxyAuth(ctx, req, resp, "NTLM")
		if err != nil {
			logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d NTLM failed: %v\n", ctx.SessionNo, err)
		}

	} else if nego {
		err := DoNegotiateProxyAuth(ctx, req, resp)
		if err != nil {
			logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Negotiate failed: %v\n", ctx.SessionNo, err)
		}
	} else if basic {
		err := DoBasicProxyAuth(ctx, req, resp)
		if err != nil {
			logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Basic failed: %v\n", ctx.SessionNo, err)
		}
	} else {
		logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d unknown authentication method: %s\n", ctx.SessionNo, bestAuth)
	}
	logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Auth done\n", ctx.SessionNo)
	for k, v := range resp.Header {
		logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d response header: %s=%s\n", ctx.SessionNo, k, v)
	}
}

func DoBasicProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(),ctx.SessionNo)
	var r = req
	var err error

	proxyUsername := readconfig.Config.Proxy.BasicUser
	proxyPassword := readconfig.Config.Proxy.BasicPass
	proxyAuth := proxyUsername + ":" + proxyPassword
	logging.Printf("DEBUG", "DoBasicProxyAuth: SessionID:%d encoded string: %s\n", ctx.SessionNo, base64.StdEncoding.EncodeToString([]byte(proxyAuth)))

	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(proxyAuth))))
	basicResp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		logging.Printf("ERROR", "DoBasicroxyAuth: SessionID:%d RoundTrip error(should not happen!): %v\n", ctx.SessionNo, err)
		if basicResp == nil {
			logging.Printf("ERROR", "DoBasicProxyAuth: SessionID:%d no basicresp RoundTrip error: %v\n", ctx.SessionNo, err)
			return err
		} else if basicResp.StatusCode != http.StatusProxyAuthRequired {
			logging.Printf("ERROR", "DoBasicProxyAuth: SessionID:%d RoundTrip error: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, basicResp)
			return err
		}
	}

	OverwriteResponse(ctx, resp, basicResp)
	logging.Printf("DEBUG", "DoBasicProxyAuth: SessionID:%d Auth done\n", ctx.SessionNo)
	return nil
}

func OverwriteResponse(ctx *httpproxy.Context, orgResp *http.Response, newResp *http.Response) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(),ctx.SessionNo)
	// Replace original response
	if newResp == nil {
		logging.Printf("DEBUG", "OverwriteResponse: SessionID:%d empty response\n", ctx.SessionNo)
		return
	}
	orgResp.StatusCode = newResp.StatusCode
	orgResp.Status = newResp.Status
	for k, _ := range orgResp.Header {
		orgResp.Header.Del(k)
		logging.Printf("DEBUG", "OverwriteResponse: SessionID:%d delete header %s\n", ctx.SessionNo, k)
	}
	for k, v := range newResp.Header {
		for i := 0; i < len(v); i++ {
			orgResp.Header.Add(k, v[i])
		}
		logging.Printf("DEBUG", "OverwriteResponse: SessionID:%d add header %s=%s\n", ctx.SessionNo, k, v)
	}
	if newResp.Body != http.NoBody {
		orgResp.Body = newResp.Body
	} else {
		orgResp.Body = http.NoBody
	}
	orgResp.ContentLength = newResp.ContentLength
	orgResp.TLS = newResp.TLS
	copy(orgResp.TransferEncoding, newResp.TransferEncoding)
}
