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
	var r = req
	var err error
	// NTLM Step 1: Send Negotiate Message
	proxyDomain := readconfig.Config.Proxy.NtlmDomain
	proxyUsername := readconfig.Config.Proxy.NtlmUser
	proxyPassword := readconfig.Config.Proxy.NtlmPass
	negotiateMessage, err := ntlmssp.NewNegotiateMessage(proxyDomain, "")
	logging.Printf("DEBUG", "DoNTLMProxyAuth: negotiateMessage %s\n", base64.StdEncoding.EncodeToString(negotiateMessage))
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: Could not negotiate domain '%s': %v\n", proxyDomain, err)
		return err
	}
	r.Header.Add("Proxy-Authorization", fmt.Sprintf("%s %s", auth, base64.StdEncoding.EncodeToString(negotiateMessage)))
	ntlmResp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: RoundTrip error(should not happen!): %v\n", err)
		if ntlmResp == nil {
			logging.Printf("ERROR", "DoNTLMProxyAuth: no ntlmresp RoundTrip error: %v\n", err)
			return err
		} else if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
			logging.Printf("ERROR", "DoNTLMProxyAuth: RoundTrip error: %v\n", err)
			return err
		}
	}
	if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
		logging.Printf("ERROR", "DoNTLMProxyAuth: Auth next %s, Error: %v\n", ntlmResp.Header.Get("Proxy-Authenticate"), err)
		return err
	}
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
	logging.Printf("DEBUG", "DoNTLMProxyAuth: ntlm> Processing NTLM challenge with username '%s' and password with length %d\n", proxyUsername, len(proxyPassword))
	authenticateMessage, err := ntlmssp.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
	if err != nil {
		logging.Printf("ERROR", "DoNTLMProxyAuth: ntlm> Could not process the NTLM challenge: %v\n", err)
		return err
	}
	logging.Printf("DBEUG", "DoNTLMProxyAuth: ntlm> NTLM authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
	r.Header.Del("Proxy-Authorization")
	r.Header.Add("Proxy-Authorization", fmt.Sprintf("%s %s", auth, base64.StdEncoding.EncodeToString(authenticateMessage)))
	ntlmResp, err = ctx.Prx.Rt.RoundTrip(r)
	if ntlmResp.StatusCode == http.StatusProxyAuthRequired {
		logging.Printf("ERROR", "DoNTLMProxyAuth: Failed\n")
		return errors.New("no NTLM OK received")
	} else {
		logging.Printf("DEBUG", "DoNTLMProxyAuth: Result %d\n", ntlmResp.StatusCode)
	}
	for k, v := range resp.Header {
		logging.Printf("DEBUG", "DoNTLMProxyAuth: response header: %s=%s\n", k, v)
	}

	// Replace original response
	resp.StatusCode = ntlmResp.StatusCode
	resp.Status = ntlmResp.Status
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
	if ntlmResp.Body != http.NoBody {
		resp.Body = ntlmResp.Body
	} else {
		resp.Body = http.NoBody
	}
	resp.ContentLength = ntlmResp.ContentLength
	resp.TLS = ntlmResp.TLS
	copy(resp.TransferEncoding, ntlmResp.TransferEncoding)
	logging.Printf("DEBUG", "DoNTLMProxyAuth: Auth done\n")
	return nil
}

func DoNegotiateProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	var r = req
	var err error
	var proxyFQDN string
	var krbClient *client.Client

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "DoNegotiateProxyAuth: proxy: %s\n", proxy)
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
		logging.Printf("ERROR", "DoNegotiateProxyAuth: Kerberos config error: %v\n", err)
	}
	if krbCredentialCache != "" {
		var krbCCache *credentials.CCache
		krbCCache, err = credentials.LoadCCache(krbCredentialCache)
		if err != nil {
			logging.Printf("ERROR", "DoNegotiateProxyAuth: cloud not load cache: %v\n", err)
		} else {
			krbClient, err = client.NewFromCCache(krbCCache, krbConfig, client.DisablePAFXFAST(true))
		}
	} else {
		krbClient = client.NewWithPassword(proxyUsername, proxyDomain, proxyPassword, krbConfig, client.DisablePAFXFAST(true))
		err = krbClient.Login()
	}
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: Kerberos client error: %v\n", err)
		if readconfig.Config.Proxy.NtlmUser != "" && readconfig.Config.Proxy.NtlmPass != "" {

			logging.Printf("DEBUG", "DoNegotiateProxyAuth: Try Negotiate / NTLM fallback: %v\n", err)
			err = DoNTLMProxyAuth(ctx, req, resp, "Negotiate")
			if err != nil {
				logging.Printf("ERROR", "DoNegotiateProxyAuth: Negotiate / NTLM fallback failed: %v\n", err)
			}
		}
		return err
	}
	krbSPN := "HTTP/" + proxyFQDN
	spnegoClient := spnego.SPNEGOClient(krbClient, krbSPN)
	err = spnegoClient.AcquireCred()
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: could not acquire spnego client credential: %v\n", err)
		return err
	}
	securityContext, err := spnegoClient.InitSecContext()
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: could not initialize security context: %v\n", err)
		return err
	}
	negoAuth, err := securityContext.Marshal()
	if err != nil {
		logging.Printf("ERROR", "DoNegotiateProxyAuth: %v\n", krberror.Errorf(err, krberror.EncodingError, "could not marshal SPNEGO"))
		return err
	}

	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString([]byte(negoAuth))))
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
		//	authenticateMessage, err := nego.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
		//	if err != nil {
		//		logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> Could not process the negotiate challenge: %v\n", err)
		//		return err
		//	}
		//	logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: ntlm> negotiate authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
		//	r.Header.Del("Proxy-Authorization")
		//	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
		//	negoResp, err = ctx.Prx.Rt.RoundTrip(r)
		return errors.New("additional negotiate round required")
		//	} else if negoResp.StatusCode != http.StatusOK {
		//		logging.Printf("INFO: Proxy: DoNegotiateProxyAuth: Failed %d\n",negoResp.StatusCode)
		//		return errors.New("no negotiate OK received")
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
