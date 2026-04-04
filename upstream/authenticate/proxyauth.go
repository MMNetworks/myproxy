// Package authenticate handles upstream proxy authentication
package authenticate

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/readconfig"
	"net/http"
	"strings"
)

type proxyAuthRoundTripper struct {
	GetContext func() *httpproxy.Context
}

func (pA *proxyAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := pA.GetContext()
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)

	conn := ctx.UpstreamConn

	if conn == nil {
		logging.Printf("ERROR", "proxyAuthRoundTripper: SessionID:%d Error getting connection info\n", ctx.SessionNo)
		return nil, errors.New("empty proxy connection")
	}
	if err := req.WriteProxy(conn); err != nil {
		logging.Printf("ERROR", "proxyAuthRoundTripper: SessionID:%d Error writing to proxy connection: %v\n", ctx.SessionNo, err)
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(conn), req)
}

// DoProxyAuth Adds upstream proxy authentication headers for client
func DoProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var err error
	ctx.Rt = &proxyAuthRoundTripper{
		GetContext: func() *httpproxy.Context {
			return ctx
		},
	}
	proxyAuthValues := resp.Header.Values("Proxy-Authenticate")
	tV := httpproxy.CleanUntrustedString(ctx, "Proxy-Authenticate", strings.Join(proxyAuthValues, ","))
	logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Proxy-Authenticate header: %s\n", ctx.SessionNo, tV)
	// Get best match
	var bestAuth string
	for _, v := range readconfig.Config.Proxy.Authentication {
		logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Determine preferred authentication method: %s|%s\n", ctx.SessionNo, v, strings.Join(proxyAuthValues[:], ","))
		authMethods := httpproxy.CleanUntrustedString(ctx, "Proxy-Authenticate", strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
		if strings.Contains(authMethods, strings.ToUpper(v)) {
			logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Preferred method: %s\n", ctx.SessionNo, v)
			bestAuth = v
			break
		}
	}
	logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Selected authentication method: %s\n", ctx.SessionNo, bestAuth)
	authMethods := httpproxy.CleanUntrustedString(ctx, "Proxy-Authenticate", strings.ToUpper(strings.Join(proxyAuthValues[:], ",")))
	ntlm := strings.Contains(authMethods, "NTLM")
	nego := strings.Contains(authMethods, "NEGOTIATE")
	basic := strings.Contains(authMethods, "BASIC")
	logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Other possible methods: NTLM,Negotiate,Basic %v,%v,%v\n", ctx.SessionNo, ntlm, nego, basic)
	bestAuthUpper := strings.ToUpper(bestAuth)
	ntlm = strings.Contains(bestAuthUpper, "NTLM")
	nego = strings.Contains(bestAuthUpper, "NEGOTIATE")
	basic = strings.Contains(bestAuthUpper, "BASIC")
	if ntlm {
		err = doNTLMProxyAuth(ctx, req, resp, "NTLM")
		if err != nil {
			logging.Printf("ERROR", "DoProxyAuth: SessionID:%d NTLM failed: %v\n", ctx.SessionNo, err)
		}

	} else if nego {
		err := doNegotiateProxyAuth(ctx, req, resp)
		if err != nil {
			logging.Printf("ERROR", "DoProxyAuth: SessionID:%d Negotiate failed: %v\n", ctx.SessionNo, err)
		}
	} else if basic {
		err := doBasicProxyAuth(ctx, req, resp)
		if err != nil {
			logging.Printf("ERROR", "DoProxyAuth: SessionID:%d Basic failed: %v\n", ctx.SessionNo, err)
		}
	} else {
		logging.Printf("INFO", "DoProxyAuth: SessionID:%d Unknown authentication method: %s\n", ctx.SessionNo, bestAuth)
	}
	logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Auth done\n", ctx.SessionNo)
	for k, v := range resp.Header {
		tK := httpproxy.CleanUntrustedString(ctx, "Header key", k)
		tV := httpproxy.CleanUntrustedString(ctx, "Header Value", strings.Join(v, ","))
		logging.Printf("DEBUG", "DoProxyAuth: SessionID:%d Response header: %s=%s\n", ctx.SessionNo, tK, tV)
	}
}

func doBasicProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var err error

	proxyUsername := readconfig.Config.Proxy.BasicUser
	proxyPassword := readconfig.Config.Proxy.BasicPass
	proxyAuth := proxyUsername + ":" + proxyPassword
	logging.Printf("DEBUG", "doBasicProxyAuth: SessionID:%d Encoded string: %s\n", ctx.SessionNo, base64.StdEncoding.EncodeToString([]byte(proxyAuth)))

	req.Header.Add("Proxy-Authorization", fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(proxyAuth))))
	basicResp, err := ctx.Rt.RoundTrip(req)
	if err != nil {
		logging.Printf("ERROR", "doBasicroxyAuth: SessionID:%d Unexpected RoundTrip error: %v\n", ctx.SessionNo, err)
		if basicResp == nil {
			logging.Printf("ERROR", "doBasicProxyAuth: SessionID:%d No basic authorisation header in RoundTrip response: %v\n", ctx.SessionNo, err)
			return err
		} else if basicResp.StatusCode != http.StatusProxyAuthRequired {
			logging.Printf("ERROR", "doBasicProxyAuth: SessionID:%d RoundTrip error: %v\n", ctx.SessionNo, err)
			overwriteResponse(ctx, resp, basicResp)
			return err
		}
	}

	overwriteResponse(ctx, resp, basicResp)
	logging.Printf("DEBUG", "doBasicProxyAuth: SessionID:%d Auth done\n", ctx.SessionNo)
	return nil
}

func overwriteResponse(ctx *httpproxy.Context, orgResp *http.Response, newResp *http.Response) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	// Replace original response
	if newResp == nil {
		logging.Printf("ERROR", "overwriteResponse: SessionID:%d Empty response\n", ctx.SessionNo)
		return
	}
	orgResp.StatusCode = newResp.StatusCode
	orgResp.Status = httpproxy.CleanUntrustedString(ctx, "Status", newResp.Status)
	for k, v := range orgResp.Header {
		orgResp.Header.Del(k)
		tK := httpproxy.CleanUntrustedString(ctx, "Header key", k)
		tV := httpproxy.CleanUntrustedString(ctx, "Header Value", strings.Join(v, ","))
		logging.Printf("DEBUG", "overwriteResponse: SessionID:%d Delete header %s:%s\n", ctx.SessionNo, tK, tV)
	}
	for k, v := range newResp.Header {
		for i := 0; i < len(v); i++ {
			orgResp.Header.Add(k, v[i])
		}
		tK := httpproxy.CleanUntrustedString(ctx, "Header key", k)
		tV := httpproxy.CleanUntrustedString(ctx, "Header Value", strings.Join(v, ","))
		logging.Printf("DEBUG", "overwriteResponse: SessionID:%d Add header %s=%s\n", ctx.SessionNo, tK, tV)
	}
	if newResp.Body != http.NoBody {
		orgResp.Body = newResp.Body
	} else {
		orgResp.Body = http.NoBody
	}
	orgResp.ContentLength = newResp.ContentLength
	orgResp.TLS = newResp.TLS
	for _, v := range newResp.TransferEncoding {
		orgResp.TransferEncoding = append(orgResp.TransferEncoding, httpproxy.CleanUntrustedString(ctx, "Transfer Encoding", v))
	}
	// copy(orgResp.TransferEncoding, newResp.TransferEncoding)
}
