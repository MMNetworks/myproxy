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
	"net/http"
	"strings"
)

func DoNTLMProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response, auth string) error {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	var r = req
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
	r.Header.Add("Proxy-Authorization", fmt.Sprintf("%s %s", auth, base64.StdEncoding.EncodeToString(negotiateMessage)))
	ntlmResp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d RoundTrip error(should not happen!): %v\n", ctx.SessionNo, err)
		if ntlmResp == nil {
			logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d no ntlmresp RoundTrip error: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, ntlmResp)
			return err
		} else if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
			logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d RoundTrip error: %v\n", ctx.SessionNo, err)
			OverwriteResponse(ctx, resp, ntlmResp)
			return err
		}
	}
	if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d Auth next %s, Error: %v\n", ntlmResp.Header.Get("Proxy-Authenticate"), ctx.SessionNo, err)
		OverwriteResponse(ctx, resp, ntlmResp)
		return err
	}
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
	logging.Printf("DEBUG", "DoNTLMProxyAuth: SessionID:%d ntlm> Processing NTLM challenge with username '%s' and password with length %d\n", ctx.SessionNo, proxyUsername, len(proxyPassword))
	authenticateMessage, err := ntlmssp.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: SessionID:%d ntlm> Could not process the NTLM challenge: %v\n", ctx.SessionNo, err)
		OverwriteResponse(ctx, resp, ntlmResp)
		return err
	}
	logging.Printf("DBEUG", "DoNTLMProxyAuth: SessionID:%d ntlm> NTLM authorization: '%s'\n", ctx.SessionNo, base64.StdEncoding.EncodeToString(authenticateMessage))
	r.Header.Del("Proxy-Authorization")
	r.Header.Add("Proxy-Authorization", fmt.Sprintf("%s %s", auth, base64.StdEncoding.EncodeToString(authenticateMessage)))
	ntlmResp, err = ctx.Prx.Rt.RoundTrip(r)
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
	var err error
	var proxyFQDN string
	var krbClient *client.Client

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d proxy: %s\n", ctx.SessionNo, proxy)
	ipos := strings.Index(proxy, ":")
	if ipos > 0 {
		proxyFQDN = proxy[0:ipos]
	} else {
		proxyFQDN = proxy
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
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d cloud not load cache: %v\n", ctx.SessionNo, err)
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
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d could not acquire spnego client credential: %v\n", ctx.SessionNo, err)
		return err
	}
	securityContext, err := spnegoClient.InitSecContext()
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d could not initialize security context: %v\n", ctx.SessionNo, err)
		return err
	}
	negoAuth, err := securityContext.Marshal()
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d %v\n", ctx.SessionNo, krberror.Errorf(err, krberror.EncodingError, "could not marshal SPNEGO"))
		return err
	}

	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString([]byte(negoAuth))))
	negoResp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d RoundTrip error(should not happen!): %v\n", ctx.SessionNo, err)
		if negoResp == nil {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d no negoresp RoundTrip error: %v\n", ctx.SessionNo, err)
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
		logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d Auth next %s\n", ctx.SessionNo, negoResp.Header.Get("Proxy-Authenticate"))
		challenge := strings.Split(negoResp.Header.Get("Proxy-Authenticate"), " ")
		if len(challenge) < 2 {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: SessionID:%d nego> The proxy did not return an negotiate challenge, got: '%s'\n", ctx.SessionNo, negoResp.Header.Get("Proxy-Authenticate"))
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
		//	authenticateMessage, err := nego.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
		//	if err != nil {
		//		logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> Could not process the negotiate challenge: %v\n", err)
		//		return err
		//	}
		//	logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: ntlm> negotiate authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
		//	r.Header.Del("Proxy-Authorization")
		//	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
		//	negoResp, err = ctx.Prx.Rt.RoundTrip(r)
		OverwriteResponse(ctx, resp, negoResp)
		return errors.New("additional negotiate round required")
		//	} else if negoResp.StatusCode != http.StatusOK {
		//		logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: Failed %d\n",negoResp.StatusCode)
		//		return errors.New("no negotiate OK received")
	}

	OverwriteResponse(ctx, resp, negoResp)
	logging.Printf("DEBUG", "DoNegotiateProxyAuth: SessionID:%d Auth done\n", ctx.SessionNo)
	return nil
}
