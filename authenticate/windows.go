//go:build windows

package authenticate

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/alexbrainman/sspi/ntlm"
	"io"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/readconfig"
	"net/http"
	"strings"
	// "github.com/yassinebenaid/godump"
)

func DoNTLMProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response, auth string) error {
	// NTLM Step 1: Send Negotiate Message
	sspiCred, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: could not acquire spnego client credential: %v\n", err)
		return err
	}
	defer sspiCred.Release()

	securityContext, ntlmToken, err := ntlm.NewClientContext(sspiCred)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: Failed to initialize security context: %v\n", err)
		return err
	}
	defer securityContext.Release()

	req.Header.Add("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(ntlmToken)))
	ntlmResp, err := ctx.Prx.Rt.RoundTrip(req)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: RoundTrip error: %v\n", err)
		return err
	}
	if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
		logging.Printf("ERROR", "DoNTLMProxyAuth: Auth next %s Error: %v\n", ntlmResp.Header.Get("Proxy-Authenticate"), err)
		return err
	}
	_, err = io.ReadAll(ntlmResp.Body)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: ntlm> Could not read response body from proxy: %v\n", err)
		return err
	}
	ntlmResp.Body.Close()
	challenge := strings.Split(ntlmResp.Header.Get("Proxy-Authenticate"), " ")
	if len(challenge) < 2 {
		logging.Printf("DEBUG", "DoNTLMProxyAuth: ntlm> The proxy did not return an NTLM challenge, got: '%s'\n", ntlmResp.Header.Get("Proxy-Authenticate"))
		return errors.New("no NTLM challenge received")
	}
	logging.Printf("DEBUG", "DoNTLMProxyAuth: ntlm> NTLM challenge: '%s'\n", challenge[1])
	challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: ntlm> Could not base64 decode the NTLM challenge: %v\n", err)
		return err
	}
	// NTLM Step 3: Send Authorization Message
	logging.Printf("DEBUG", "DoNTLMProxyAuth: ntlm> Processing NTLM challenge\n")
	authenticateMessage, err := securityContext.Update(challengeMessage)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: ntlm> Could not process the NTLM challenge: %v\n", err)
		return err
	}
	defer securityContext.Release()
	logging.Printf("DEBUG", "DoNTLMProxyAuth: ntlm> NTLM authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
	req.Header.Del("Proxy-Authorization")
	req.Header.Add("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
	ntlmResp, err = ctx.Prx.Rt.RoundTrip(req)
	if ntlmResp.StatusCode == http.StatusProxyAuthRequired {
		logging.Printf("ERROR", "DoNTLMProxyAuth: Failed\n")
		return errors.New("no NTLM OK received")
	} else {
		logging.Printf("DEBUG", "DoNTLMProxyAuth: Result %d\n", ntlmResp.StatusCode)
	}
	for k, v := range ntlmResp.Header {
		logging.Printf("DEBUG", "DoNTLMProxyAuth: response header: %s=%s\n", k, v)
	}

	// Replace original response
	resp.StatusCode = ntlmResp.StatusCode
	for k, _ := range resp.Header {
		resp.Header.Del(k)
		logging.Printf("DEBUG", "DoNTLMProxyAuth: delete header %s\n", k)
	}
	for k, v := range ntlmResp.Header {
		for i := 0; i < len(v); i++ {
			resp.Header.Add(k, v[i])
		}
		logging.Printf("DEBUG", "DoNTLMProxyAuth: add header %s=%s\n", k, v)
	}
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: ntlm> Could not read response body from proxy: %v\n", err)
		return err
	}
	resp.Body.Close()
	resp.Body = ntlmResp.Body
	resp.ContentLength = ntlmResp.ContentLength
	copy(resp.TransferEncoding, ntlmResp.TransferEncoding)
	logging.Printf("DEBUG", "DoNTLMProxyAuth: Auth done\n")
	return nil
}

func DoNegotiateProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	var r = req
	var proxyFQDN string

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "DoNegotiateProxyAuth: proxy: %s\n", proxy)
	ipos := strings.Index(proxy, ":")
	if ipos > 0 {
		proxyFQDN = proxy[0:ipos]
	} else {
		proxyFQDN = proxy
	}

	proxyDomain := readconfig.Config.Proxy.KerberosDomain

	sspiCred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: could not acquire spnego client credential: %v\n", err)
		return err
	}
	defer sspiCred.Release()

	servicePrincipalName := "HTTP/" + proxyFQDN + "@" + proxyDomain
	logging.Printf("DEBUG", "DoNegotiateProxyAuth: serviceprincipalname: %s\n", servicePrincipalName)
	securityContext, negoToken, err := negotiate.NewClientContext(sspiCred, servicePrincipalName)
	if err != nil {
		fmt.Printf("ERROR", "DoNegotiateProxyAuth: Failed to initialize security context: %v\n", err)
		return err
	}
	defer securityContext.Release()

	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(negoToken)))
	negoResp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: RoundTrip error(should not happen!): %v\n", err)
		if negoResp == nil {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: no negoresp RoundTrip error: %v\n", err)
			return err
		} else if negoResp.StatusCode != http.StatusProxyAuthRequired {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: RoundTrip error: %v\n", err)
			return err
		}
	}
	if negoResp.StatusCode == http.StatusProxyAuthRequired {
		// need really a loop, but unlikely to happen in real life
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: Auth next %s\n", negoResp.Header.Get("Proxy-Authenticate"))
		challenge := strings.Split(negoResp.Header.Get("Proxy-Authenticate"), " ")
		if len(challenge) < 2 {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: nego> The proxy did not return an negotiate challenge, got: '%s'\n", negoResp.Header.Get("Proxy-Authenticate"))
			return errors.New("no Negotiate challenge received")
		}
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: nego> negotiate challenge: '%s'\n", challenge[1])
		challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
		if err != nil {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: nego> Could not base64 decode the Negotiate challenge: %v\n", err)
			return err
		}
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: nego> negotiate authorization '%s'\n", base64.StdEncoding.EncodeToString(challengeMessage))
		//      authenticateMessage, err := nego.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
		//      if err != nil {
		//              logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> Could not process the negotiate challenge: %v\n", err)
		//              return err
		//      }
		//      logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: ntlm> negotiate authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
		//      r.Header.Del("Proxy-Authorization")
		//      r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
		//      negoResp, err = ctx.Prx.Rt.RoundTrip(r)
		return errors.New("additional negotiate round required")
		//      } else if negoResp.StatusCode != http.StatusOK {
		//              logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: Failed %d\n",negoResp.StatusCode)
		//              return errors.New("no negotiate OK received")
	}
	for k, v := range resp.Header {
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: response header: %s=%s\n", k, v)
	}

	// Replace original response
	resp.StatusCode = negoResp.StatusCode
	resp.Status = negoResp.Status
	for k, _ := range resp.Header {
		resp.Header.Del(k)
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: delete header %s\n", k)
	}
	for k, v := range negoResp.Header {
		for i := 0; i < len(v); i++ {
			resp.Header.Add(k, v[i])
		}
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: add header %s=%s\n", k, v)
	}
	if negoResp.Body != http.NoBody {
		resp.Body = negoResp.Body
	} else {
		resp.Body = http.NoBody
	}
	resp.ContentLength = negoResp.ContentLength
	resp.TLS = negoResp.TLS
	copy(resp.TransferEncoding, negoResp.TransferEncoding)
	logging.Printf("DEBUG", "DoNegotiateProxyAuth: Auth done\n")
	return nil
}
