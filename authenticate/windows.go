//go:build windows

package authenticate

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	//        "regexp"
	"encoding/base64"
	"github.com/Azure/go-ntlmssp"
	"io"
	"myproxy/http-proxy"
	"myproxy/readconfig"
	"strings"
	// "github.com/yassinebenaid/godump"
)

func DoNTLMProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	// NTLM Step 1: Send Negotiate Message
	proxyDomain := readconfig.Config.Proxy.NtlmDomain
	proxyUsername := readconfig.Config.Proxy.NtlmUser
	proxyPassword := readconfig.Config.Proxy.NtlmPass
	negotiateMessage, err := ntlmssp.NewNegotiateMessage(proxyDomain, "")
	log.Printf("INFO: Proxy: DoNTLMProxyAuth: negotiateMessage %s\n", base64.StdEncoding.EncodeToString(negotiateMessage))
	if err != nil {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: Could not negotiate domain '%s': %s\n", proxyDomain, err)
		return err
	}
	req.Header.Add("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(negotiateMessage)))
	ntlmResp, err := ctx.Prx.Rt.RoundTrip(req)
	if err != nil {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: RoundTrip error: %v\n", err)
		return err
	}
	if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: Auth next %s\n", ntlmResp.Header.Get("Proxy-Authenticate"))
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: Error: %v\n", err)
		return err
	}
	_, err = io.ReadAll(ntlmResp.Body)
	if err != nil {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: ntlm> Could not read response body from proxy: %s", err)
		return err
	}
	ntlmResp.Body.Close()
	challenge := strings.Split(ntlmResp.Header.Get("Proxy-Authenticate"), " ")
	if len(challenge) < 2 {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: ntlm> The proxy did not return an NTLM challenge, got: '%s'\n", ntlmResp.Header.Get("Proxy-Authenticate"))
		return errors.New("no NTLM challenge received")
	}
	log.Printf("INFO: Proxy: DoNTLMProxyAuth: ntlm> NTLM challenge: '%s'\n", challenge[1])
	challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
	if err != nil {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: ntlm> Could not base64 decode the NTLM challenge: %s\n", err)
		return err
	}
	// NTLM Step 3: Send Authorization Message
	log.Printf("INFO: Proxy: DoNTLMProxyAuth: ntlm> Processing NTLM challenge with username '%s' and password with length %d\n", proxyUsername, len(proxyPassword))
	authenticateMessage, err := ntlmssp.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
	if err != nil {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: ntlm> Could not process the NTLM challenge: %s\n", err)
		return err
	}
	log.Printf("INFO: Proxy: DoNTLMProxyAuth: ntlm> NTLM authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
	req.Header.Del("Proxy-Authorization")
	req.Header.Add("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
	ntlmResp, err = ctx.Prx.Rt.RoundTrip(req)
	if ntlmResp.StatusCode == http.StatusProxyAuthRequired {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: Failed\n")
		return errors.New("no NTLM OK received")
	} else {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: Result %d", ntlmResp.StatusCode)
	}
	for k, v := range ntlmResp.Header {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: response header: %s=%s\n", k, v)
	}

	// Replace original response
	resp.StatusCode = ntlmResp.StatusCode
	for k, _ := range resp.Header {
		resp.Header.Del(k)
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: delete header %s", k)
	}
	for k, v := range ntlmResp.Header {
		for i := 0; i < len(v); i++ {
			resp.Header.Add(k, v[i])
		}
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: add header %s=%s", k, v)
	}
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: ntlm> Could not read response body from proxy: %s", err)
		return err
	}
	resp.Body.Close()
	resp.Body = ntlmResp.Body
	resp.ContentLength = ntlmResp.ContentLength
	copy(resp.TransferEncoding, ntlmResp.TransferEncoding)
	return nil
}

func DoNegotiateProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	return nil
}
