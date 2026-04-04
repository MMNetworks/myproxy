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
	"net"
	"net/http"
	"strings"
	// "github.com/yassinebenaid/godump"
)

func doNTLMProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response, auth string) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	// NTLM Step 1: Send Negotiate Message
	sspiCred, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil {
		logging.Printf("ERROR", "doNTLMProxyAuth: SessionID:%d Could not acquire spnego client credential: %v\n", ctx.SessionNo, err)
		return err
	}
	defer func() { _ = sspiCred.Release() }()

	securityContext, ntlmToken, err := ntlm.NewClientContext(sspiCred)
	if err != nil {
		logging.Printf("ERROR", "doNTLMProxyAuth: SessionID:%d Failed to initialize security context: %v\n", ctx.SessionNo, err)
		return err
	}
	defer func() { _ = securityContext.Release() }()

	req.Header.Add("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(ntlmToken)))
	ntlmResp, err := ctx.Rt.RoundTrip(req)
	if err != nil {
		logging.Printf("ERROR", "doNTLMProxyAuth: SessionID:%d RoundTrip error: %v\n", ctx.SessionNo, err)
		overwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
		proxyAuthValues := httpproxy.CleanUntrustedString(ctx, "Proxy-Authenticate", ntlmResp.Header.Get("Proxy-Authenticate"))
		logging.Printf("ERROR", "doNTLMProxyAuth: SessionID:%d Supported authentication methods: %s\n", ctx.SessionNo, proxyAuthValues)
		overwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	_, err = io.ReadAll(ntlmResp.Body)
	if err != nil {
		logging.Printf("ERROR", "doNTLMProxyAuth: SessionID:%d Could not read response body from proxy: %v\n", ctx.SessionNo, err)
		overwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	_ = ntlmResp.Body.Close()
	challenge := strings.Split(httpproxy.CleanUntrustedString(ctx, "Proxy-Authenticate", ntlmResp.Header.Get("Proxy-Authenticate")), " ")
	if len(challenge) < 2 {
		proxyAuthValues := httpproxy.CleanUntrustedString(ctx, "Proxy-Authenticate", ntlmResp.Header.Get("Proxy-Authenticate"))
		logging.Printf("ERROR", "doNTLMProxyAuth: SessionID:%d The proxy did not return an NTLM challenge, got: '%s'\n", ctx.SessionNo, proxyAuthValues)
		overwriteResponse(ctx, resp, ntlmResp)
		return errors.New("no NTLM challenge received")
	}
	logging.Printf("DEBUG", "doNTLMProxyAuth: SessionID:%d NTLM challenge: '%s'\n", ctx.SessionNo, challenge[1])
	challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
	if err != nil {
		logging.Printf("ERROR", "doNTLMProxyAuth: SessionID:%d Could not base64 decode the NTLM challenge: %v\n", ctx.SessionNo, err)
		overwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	// NTLM Step 3: Send Authorization Message
	logging.Printf("DEBUG", "doNTLMProxyAuth: SessionID:%d Processing NTLM challenge\n", ctx.SessionNo)
	authenticateMessage, err := securityContext.Update(challengeMessage)
	if err != nil {
		logging.Printf("ERROR", "doNTLMProxyAuth: SessionID:%d Could not process the NTLM challenge: %v\n", ctx.SessionNo, err)
		overwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	defer func() { _ = securityContext.Release() }()
	logging.Printf("DEBUG", "doNTLMProxyAuth: SessionID:%d NTLM authorization: '%s'\n", ctx.SessionNo, base64.StdEncoding.EncodeToString(authenticateMessage))
	req.Header.Del("Proxy-Authorization")
	req.Header.Add("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
	ntlmResp, err = ctx.Rt.RoundTrip(req)
	if ntlmResp == nil {
		logging.Printf("ERROR", "doNTLMProxyAuth: SessionID:%d NTLM Authentication failed. %v\n", ctx.SessionNo, err)
		return errors.New("empty response received")
	} else if ntlmResp.StatusCode == http.StatusProxyAuthRequired {
		logging.Printf("ERROR", "doNTLMProxyAuth: SessionID:%d NTLM Authentication failed\n", ctx.SessionNo)
		overwriteResponse(ctx, resp, ntlmResp)
		return errors.New("no NTLM OK received")
	} else {
		logging.Printf("DEBUG", "doNTLMProxyAuth: SessionID:%d NTLM Authentication result %d\n", ctx.SessionNo, ntlmResp.StatusCode)
	}

	overwriteResponse(ctx, resp, ntlmResp)
	logging.Printf("DEBUG", "doNTLMProxyAuth: SessionID:%d Auth done\n", ctx.SessionNo)
	return nil
}

func doNegotiateProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var err error
	var proxyFQDN string
	var servicePrincipalName string

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "doNegotiateProxyAuth: SessionID:%d Use upstream proxy: %s\n", ctx.SessionNo, proxy)
	proxyFQDN, _, err = net.SplitHostPort(proxy)
	if err != nil {
		// if errors.Is(err, net.ErrMissingPort) {
		if strings.Contains(err.Error(), "missing port in address") {
			proxyFQDN = proxy
		} else {
			logging.Printf("ERROR", "doNegotiateProxyAuth: SessionID:%d Could not convert proxy ip %s: %v\n", ctx.SessionNo, proxy, err)
			return err
		}
	}

	proxyDomain := readconfig.Config.Proxy.KerberosDomain

	sspiCred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		logging.Printf("ERROR", "doNegotiateProxyAuth: SessionID:%d Could not acquire spnego client credential: %v\n", ctx.SessionNo, err)
		return err
	}
	defer func() { _ = sspiCred.Release() }()

	if proxyDomain == "" {
		servicePrincipalName = "HTTP/" + proxyFQDN
	} else {
		servicePrincipalName = "HTTP/" + proxyFQDN + "@" + proxyDomain
	}
	logging.Printf("DEBUG", "doNegotiateProxyAuth: SessionID:%d Use serviceprincipalname: %s\n", ctx.SessionNo, servicePrincipalName)
	securityContext, negoToken, err := negotiate.NewClientContext(sspiCred, servicePrincipalName)
	if err != nil {
		logging.Printf("ERROR", "doNegotiateProxyAuth: SessionID:%d Failed to initialize security context: %v\n", ctx.SessionNo, err)
		return err
	}
	defer func() { _ = securityContext.Release() }()

	req.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(negoToken)))
	negoResp, err := ctx.Rt.RoundTrip(req)
	if err != nil {
		logging.Printf("ERROR", "doNegotiateProxyAuth: SessionID:%d Unexpected RoundTrip error: %v\n", ctx.SessionNo, err)
		if negoResp == nil {
			logging.Printf("ERROR", "doNegotiateProxyAuth: SessionID:%d No negotiate autorisation header in RoundTrip response: %v\n", ctx.SessionNo, err)
			overwriteResponse(ctx, resp, negoResp)
			return err
		} else if negoResp.StatusCode != http.StatusProxyAuthRequired {
			logging.Printf("ERROR", "doNegotiateProxyAuth: SessionID:%d RoundTrip error: %v\n", ctx.SessionNo, err)
			overwriteResponse(ctx, resp, negoResp)
			return err
		}
	}
	if negoResp.StatusCode == http.StatusProxyAuthRequired {
		// need really a loop, but unlikely to happen in real life
		proxyAuthValues := httpproxy.CleanUntrustedString(ctx, "Proxy-Authenticate", negoResp.Header.Get("Proxy-Authenticate"))
		logging.Printf("DEBUG", "doNegotiateProxyAuth: SessionID:%d Supported authentication methods: %s\n", ctx.SessionNo, proxyAuthValues)
		challenge := strings.Split(httpproxy.CleanUntrustedString(ctx, "Proxy-Authenticate", negoResp.Header.Get("Proxy-Authenticate")), " ")
		if len(challenge) < 2 {
			proxyAuthValues := httpproxy.CleanUntrustedString(ctx, "Proxy-Authenticate", negoResp.Header.Get("Proxy-Authenticate"))
			logging.Printf("ERROR", "doNegotiateProxyAuth: SessionID:%d The proxy did not return a negotiate challenge, got: '%s'\n", ctx.SessionNo, proxyAuthValues)
			overwriteResponse(ctx, resp, negoResp)
			return errors.New("no Negotiate challenge received")
		}
		logging.Printf("DEBUG", "doNegotiateProxyAuth: SessionID:%d Negotiate challenge: '%s'\n", ctx.SessionNo, challenge[1])
		challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
		if err != nil {
			logging.Printf("ERROR", "doNegotiateProxyAuth: SessionID:%d Could not base64 decode the Negotiate challenge: %v\n", ctx.SessionNo, err)
			overwriteResponse(ctx, resp, negoResp)
			return err
		}
		logging.Printf("DEBUG", "doNegotiateProxyAuth: SessionID:%d Negotiate authorization '%s'\n", ctx.SessionNo, base64.StdEncoding.EncodeToString(challengeMessage))
		//      authenticateMessage, err := nego.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
		//      if err != nil {
		//              logging.Printf("INFO" "Proxy: doNegotiateProxyAuth: nego> Could not process the negotiate challenge: %v\n", err)
		//              return err
		//      }
		//      logging.Printf("INFO", "Proxy: doNegotiateProxyAuth: ntlm> negotiate authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
		//      r.Header.Del("Proxy-Authorization")
		//      r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
		//      negoResp, err = ctx.Rt.RoundTrip(req)
		overwriteResponse(ctx, resp, negoResp)
		return errors.New("additional negotiate round required")
		//      } else if negoResp.StatusCode != http.StatusOK {
		//              logging.Printf("INFO", "Proxy: doNegotiateProxyAuth: Failed %d\n",negoResp.StatusCode)
		//              return errors.New("no negotiate OK received")
	}
	for k, v := range resp.Header {
		tK := httpproxy.CleanUntrustedString(ctx, "Header key", k)
		tV := httpproxy.CleanUntrustedString(ctx, "Header Value", strings.Join(v, ","))
		logging.Printf("DEBUG", "doNegotiateProxyAuth: SessionID:%d Response header: %s=%s\n", ctx.SessionNo, tK, tV)
	}

	logging.Printf("DEBUG", "doNegotiateProxyAuth: SessionID:%d Result %d\n", ctx.SessionNo, negoResp.StatusCode)
	overwriteResponse(ctx, resp, negoResp)
	logging.Printf("DEBUG", "doNegotiateProxyAuth: SessionID:%d Auth done\n", ctx.SessionNo)
	return nil
}
