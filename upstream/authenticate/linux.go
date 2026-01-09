//go:build !windows

package authenticate

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/Azure/go-ntlmssp"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/readconfig"
	"net"
	"net/http"
	"strings"
)

func DoNTLMProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response, auth string) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var err error
	// NTLM Step 1: Send Negotiate Message
	proxyDomain := readconfig.Config.Proxy.NtlmDomain
	proxyUsername := readconfig.Config.Proxy.NtlmUser
	proxyPassword := readconfig.Config.Proxy.NtlmPass
	negotiateMessage, err := ntlmssp.NewNegotiateMessage(proxyDomain, "")
	logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d negotiateMessage %s\n", ctx.SessionNo, base64.StdEncoding.EncodeToString(negotiateMessage))
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Could not negotiate domain '%s': %v\n", ctx.SessionNo, proxyDomain, err)
		return err
	}
	req.Header.Add("Proxy-Authorization", fmt.Sprintf("%s %s", auth, base64.StdEncoding.EncodeToString(negotiateMessage)))
	ntlmResp, err := ctx.Rt.RoundTrip(req)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Unexpected RoundTrip error: %v\n", ctx.SessionNo, err)
		if ntlmResp == nil {
			logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d No ntlm authorisation header in RoundTrip response: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, ntlmResp)
			return err
		} else if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
			logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d RoundTrip error: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, ntlmResp)
			return err
		}
	}
	if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Supported authentication methods: %s\n", ntlmResp.Header.Get("Proxy-Authenticate"), ctx.SessionNo)
		OverwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	challenge := strings.Split(ntlmResp.Header.Get("Proxy-Authenticate"), " ")
	if len(challenge) < 2 {
		logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d The proxy did not return an NTLM challenge, got: '%s'\n", ctx.SessionNo, ntlmResp.Header.Get("Proxy-Authenticate"))
		OverwriteResponse(ctx, resp, ntlmResp)
		return errors.New("no NTLM challenge received")
	}
	logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d NTLM challenge: '%s'\n", ctx.SessionNo, challenge[1])
	challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Could not base64 decode the NTLM challenge: %v\n", ctx.SessionNo, err)
		OverwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	// NTLM Step 3: Send Authorization Message
	logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d Processing NTLM challenge with username '%s' and password with length %d\n", ctx.SessionNo, proxyUsername, len(proxyPassword))
	authenticateMessage, err := ntlmssp.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Could not process the NTLM challenge: %v\n", ctx.SessionNo, err)
		OverwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	logging.Printf("DBEUG", "DoNTLMProxyAuth: SessionID:%d NTLM authorization: '%s'\n", ctx.SessionNo, base64.StdEncoding.EncodeToString(authenticateMessage))
	req.Header.Del("Proxy-Authorization")
	req.Header.Add("Proxy-Authorization", fmt.Sprintf("%s %s", auth, base64.StdEncoding.EncodeToString(authenticateMessage)))
	ntlmResp, err = ctx.Rt.RoundTrip(req)
	if ntlmResp == nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Authentication failed. %v\n", ctx.SessionNo, err)
		return errors.New("empty response received")
	} else if ntlmResp.StatusCode == http.StatusProxyAuthRequired {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Authentication failed\n", ctx.SessionNo)
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
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var err error
	var proxyFQDN string
	var krbClient *client.Client

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d Use upstream proxy: %s\n", ctx.SessionNo, proxy)
	proxyFQDN, _, err = net.SplitHostPort(proxy)
	if err != nil {
		// if errors.Is(err, net.ErrMissingPort) {
		if strings.Contains(err.Error(), "missing port in address") {
			proxyFQDN = proxy
		} else {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d Could not convert proxy ip %s: %v\n", ctx.SessionNo, proxy, err)
			return err
		}
	}

	// Kerberos
	krbConfigFile := readconfig.Config.Proxy.KerberosConfig
	krbCredentialCache := readconfig.Config.Proxy.KerberosCache
	proxyDomain := readconfig.Config.Proxy.KerberosDomain
	proxyUsername := readconfig.Config.Proxy.KerberosUser
	proxyPassword := readconfig.Config.Proxy.KerberosPass

	//adding proxy authentication
	krbConfig, err := config.Load(krbConfigFile)
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d Kerberos config error: %v\n", ctx.SessionNo, err)
	}
	if krbCredentialCache != "" {
		var krbCCache *credentials.CCache
		krbCCache, err = credentials.LoadCCache(krbCredentialCache)
		if err != nil {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d Cloud not load cache: %v\n", ctx.SessionNo, err)
		} else {
			krbClient, err = client.NewFromCCache(krbCCache, krbConfig, client.DisablePAFXFAST(true))
		}
	} else {
		krbClient = client.NewWithPassword(proxyUsername, proxyDomain, proxyPassword, krbConfig, client.DisablePAFXFAST(true))
		err = krbClient.Login()
	}
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d Kerberos client error: %v\n", ctx.SessionNo, err)
		if readconfig.Config.Proxy.NtlmUser != "" && readconfig.Config.Proxy.NtlmPass != "" {

			logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d Try Negotiate / NTLM fallback: %v\n", ctx.SessionNo, err)
			err = DoNTLMProxyAuth(ctx, req, resp, "Negotiate")
			if err != nil {
				logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d Negotiate / NTLM fallback failed: %v\n", ctx.SessionNo, err)
			}
		}
		return err
	}
	krbSPN := "HTTP/" + proxyFQDN
	spnegoClient := spnego.SPNEGOClient(krbClient, krbSPN)
	err = spnegoClient.AcquireCred()
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d Could not acquire spnego client credential: %v\n", ctx.SessionNo, err)
		return err
	}
	securityContext, err := spnegoClient.InitSecContext()
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d Could not initialize security context: %v\n", ctx.SessionNo, err)
		return err
	}
	negoAuth, err := securityContext.Marshal()
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d %v\n", ctx.SessionNo, krberror.Errorf(err, krberror.EncodingError, "could not marshal SPNEGO"))
		return err
	}

	req.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString([]byte(negoAuth))))
	negoResp, err := ctx.Rt.RoundTrip(req)
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d Unexpected RoundTrip error: %v\n", ctx.SessionNo, err)
		if negoResp == nil {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d No negotiate authorisation header in RoundTrip response: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, negoResp)
			return err
		} else if negoResp.StatusCode != http.StatusProxyAuthRequired {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: RoundTrip error: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, negoResp)
			return err
		}
	}
	if negoResp.StatusCode == http.StatusProxyAuthRequired {
		// need really a loop, but unlikely to happen in real life
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d Supported authentication methods: %s\n", ctx.SessionNo, negoResp.Header.Get("Proxy-Authenticate"))
		challenge := strings.Split(negoResp.Header.Get("Proxy-Authenticate"), " ")
		if len(challenge) < 2 {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d The proxy did not return an negotiate challenge, got: '%s'\n", ctx.SessionNo, negoResp.Header.Get("Proxy-Authenticate"))
			OverwriteResponse(ctx, resp, negoResp)
			return errors.New("no Negotiate challenge received")
		}
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d negotiate challenge: '%s'\n", ctx.SessionNo, challenge[1])
		challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
		if err != nil {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d Could not base64 decode the Negotiate challenge: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, negoResp)
			return err
		}
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d negotiate authorization '%s'\n", ctx.SessionNo, base64.StdEncoding.EncodeToString(challengeMessage))
		//	authenticateMessage, err := nego.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
		//	if err != nil {
		//		logging.Printf("INFO", "Proxy: DoNegotiateProxyAuth: nego> Could not process the negotiate challenge: %v\n", err)
		//		return err
		//	}
		//	logging.Printf("INFO", "Proxy: DoNegotiateProxyAuth: ntlm> negotiate authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
		//	r.Header.Del("Proxy-Authorization")
		//	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
		//	negoResp, err = ctx.Rt.RoundTrip(req)
		OverwriteResponse(ctx, resp, negoResp)
		return errors.New("additional negotiate round required")
		//	} else if negoResp.StatusCode != http.StatusOK {
		//		logging.Printf("INFO", "Proxy: DoNegotiateProxyAuth: Failed %d\n",negoResp.StatusCode)
		//		return errors.New("no negotiate OK received")
	}

	logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d Result %d\n", ctx.SessionNo, negoResp.StatusCode)
	OverwriteResponse(ctx, resp, negoResp)
	logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d Auth done\n", ctx.SessionNo)
	return nil
}
