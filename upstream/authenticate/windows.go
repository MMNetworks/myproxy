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
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	// NTLM Step 1: Send Negotiate Message
	sspiCred, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d could not acquire spnego client credential: %v\n", ctx.SessionNo, err)
		return err
	}
	defer sspiCred.Release()

	securityContext, ntlmToken, err := ntlm.NewClientContext(sspiCred)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Failed to initialize security context: %v\n", ctx.SessionNo, err)
		return err
	}
	defer securityContext.Release()

	req.Header.Add("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(ntlmToken)))
	ntlmResp, err := ctx.Prx.Rt.RoundTrip(req)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d RoundTrip error: %v\n", ctx.SessionNo, err)
		OverwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Auth next %s Error: %v\n", ctx.SessionNo, ntlmResp.Header.Get("Proxy-Authenticate"), err)
		OverwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	_, err = io.ReadAll(ntlmResp.Body)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d ntlm> Could not read response body from proxy: %v\n", ctx.SessionNo, err)
		OverwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	ntlmResp.Body.Close()
	challenge := strings.Split(ntlmResp.Header.Get("Proxy-Authenticate"), " ")
	if len(challenge) < 2 {
		logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d ntlm> The proxy did not return an NTLM challenge, got: '%s'\n", ctx.SessionNo, ntlmResp.Header.Get("Proxy-Authenticate"))
		OverwriteResponse(ctx, resp, ntlmResp)
		return errors.New("no NTLM challenge received")
	}
	logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d ntlm> NTLM challenge: '%s'\n", ctx.SessionNo, challenge[1])
	challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d ntlm> Could not base64 decode the NTLM challenge: %v\n", ctx.SessionNo, err)
		OverwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	// NTLM Step 3: Send Authorization Message
	logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d ntlm> Processing NTLM challenge\n")
	authenticateMessage, err := securityContext.Update(challengeMessage)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d ntlm> Could not process the NTLM challenge: %v\n", ctx.SessionNo, err)
		OverwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	defer securityContext.Release()
	logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d ntlm> NTLM authorization: '%s'\n", ctx.SessionNo, base64.StdEncoding.EncodeToString(authenticateMessage))
	req.Header.Del("Proxy-Authorization")
	req.Header.Add("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
	ntlmResp, err = ctx.Prx.Rt.RoundTrip(req)
	if ntlmResp == nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Failed. %v\n", ctx.SessionNo, err)
		return errors.New("empty response received")
	} else if ntlmResp.StatusCode == http.StatusProxyAuthRequired {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Failed\n", ctx.SessionNo)
		OverwriteResponse(ctx, resp, ntlmResp)
		return errors.New("no NTLM OK received")
	} else {
		logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d Result %d\n", ctx.SessionNo, ntlmResp.StatusCode)
	}

	OverwriteResponse(ctx, resp, ntlmResp)
	logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d Auth done\n", ctx.SessionNo)
	return nil
}

func DoNegotiateProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	var r = req
	var proxyFQDN string
	var servicePrincipalName string

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d proxy: %s\n", ctx.SessionNo, proxy)
	ipos := strings.Index(proxy, ":")
	if ipos > 0 {
		proxyFQDN = proxy[0:ipos]
	} else {
		proxyFQDN = proxy
	}

	proxyDomain := readconfig.Config.Proxy.KerberosDomain

	sspiCred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d could not acquire spnego client credential: %v\n", ctx.SessionNo, err)
		return err
	}
	defer sspiCred.Release()

	if proxyDomain == "" {
		servicePrincipalName = "HTTP/" + proxyFQDN
	} else {
		servicePrincipalName = "HTTP/" + proxyFQDN + "@" + proxyDomain
	}
	logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d serviceprincipalname: %s\n", ctx.SessionNo, servicePrincipalName)
	securityContext, negoToken, err := negotiate.NewClientContext(sspiCred, servicePrincipalName)
	if err != nil {
		fmt.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d Failed to initialize security context: %v\n", ctx.SessionNo, err)
		return err
	}
	defer securityContext.Release()

	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(negoToken)))
	negoResp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d RoundTrip error(should not happen!): %v\n", ctx.SessionNo, err)
		if negoResp == nil {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d no negoresp RoundTrip error: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, negoResp)
			return err
		} else if negoResp.StatusCode != http.StatusProxyAuthRequired {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d RoundTrip error: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, negoResp)
			return err
		}
	}
	if negoResp.StatusCode == http.StatusProxyAuthRequired {
		// need really a loop, but unlikely to happen in real life
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d Auth next %s\n", ctx.SessionNo, negoResp.Header.Get("Proxy-Authenticate"))
		challenge := strings.Split(negoResp.Header.Get("Proxy-Authenticate"), " ")
		if len(challenge) < 2 {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d nego> The proxy did not return a negotiate challenge, got: '%s'\n", ctx.SessionNo, negoResp.Header.Get("Proxy-Authenticate"))
			OverwriteResponse(ctx, resp, negoResp)
			return errors.New("no Negotiate challenge received")
		}
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d nego> negotiate challenge: '%s'\n", ctx.SessionNo, challenge[1])
		challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
		if err != nil {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d nego> Could not base64 decode the Negotiate challenge: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, negoResp)
			return err
		}
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d nego> negotiate authorization '%s'\n", ctx.SessionNo, base64.StdEncoding.EncodeToString(challengeMessage))
		//      authenticateMessage, err := nego.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
		//      if err != nil {
		//              logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> Could not process the negotiate challenge: %v\n", err)
		//              return err
		//      }
		//      logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: ntlm> negotiate authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
		//      r.Header.Del("Proxy-Authorization")
		//      r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
		//      negoResp, err = ctx.Prx.Rt.RoundTrip(r)
		OverwriteResponse(ctx, resp, negoResp)
		return errors.New("additional negotiate round required")
		//      } else if negoResp.StatusCode != http.StatusOK {
		//              logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: Failed %d\n",negoResp.StatusCode)
		//              return errors.New("no negotiate OK received")
	}
	for k, v := range resp.Header {
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d response header: %s=%s\n", ctx.SessionNo, k, v)
	}

	OverwriteResponse(ctx, resp, negoResp)
	logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d Auth done\n", ctx.SessionNo)
	return nil
}
