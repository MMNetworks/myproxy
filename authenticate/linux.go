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
	"log"
	"myproxy/http-proxy"
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
	log.Printf("INFO: Proxy: DoNTLMProxyAuth: negotiateMessage %s\n", base64.StdEncoding.EncodeToString(negotiateMessage))
	if err != nil {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: Could not negotiate domain '%s': %s\n", proxyDomain, err)
		return err
	}
	r.Header.Add("Proxy-Authorization", fmt.Sprintf("%s %s", auth, base64.StdEncoding.EncodeToString(negotiateMessage)))
	ntlmResp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: RoundTrip error(should not happen!): %v\n", err)
		if ntlmResp == nil {
			log.Printf("INFO: Proxy: DoNTLMProxyAuth: no ntlmresp RoundTrip error: %v\n", err)
			return err
		} else if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
			log.Printf("INFO: Proxy: DoNTLMProxyAuth: RoundTrip error: %v\n", err)
			return err
		}
	}
	if ntlmResp.StatusCode != http.StatusProxyAuthRequired {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: Auth next %s\n", ntlmResp.Header.Get("Proxy-Authenticate"))
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: Error: %v\n", err)
		return err
	}
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
	r.Header.Del("Proxy-Authorization")
	r.Header.Add("Proxy-Authorization", fmt.Sprintf("%s %s", auth, base64.StdEncoding.EncodeToString(authenticateMessage)))
	ntlmResp, err = ctx.Prx.Rt.RoundTrip(r)
	if ntlmResp.StatusCode == http.StatusProxyAuthRequired {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: Failed\n")
		return errors.New("no NTLM OK received")
	} else {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: Result %d", ntlmResp.StatusCode)
	}
	for k, v := range resp.Header {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: response header: %s=%s\n", k, v)
	}

	// Replace original response
	resp.StatusCode = ntlmResp.StatusCode
	resp.Status = ntlmResp.Status
	for k, _ := range resp.Header {
		resp.Header.Del(k)
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: delete header %s\n", k)
	}
	for k, v := range ntlmResp.Header {
		for i := 0; i < len(v); i++ {
			resp.Header.Add(k, v[i])
		}
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: add header %s=%s\n", k, v)
	}
	if ntlmResp.Body != http.NoBody {
		resp.Body = ntlmResp.Body
	} else {
		resp.Body = http.NoBody
	}
	resp.ContentLength = ntlmResp.ContentLength
	resp.TLS = ntlmResp.TLS
	copy(resp.TransferEncoding, ntlmResp.TransferEncoding)
	log.Printf("INFO: Proxy: DoNTLMProxyAuth: Auth done\n")
	return nil
}

func DoNegotiateProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response) error {
	var r = req
	var err error
	var proxyFQDN string
	var krbClient *client.Client

	proxy := ctx.UpstreamProxy

	log.Printf("INFO: Proxy: DoNegotiateProxyAuth: proxy: %s\n", proxy)
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
		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: Kerberos config error: %v\n", err)
	}
	if krbCredentialCache != "" {
		krbCCache, err := credentials.LoadCCache(krbCredentialCache)
		if err != nil {
			log.Printf("INFO: Proxy: DoNegotiateProxyAuth: cloud not load cache: %v\n", err)
		}
		krbClient, err = client.NewFromCCache(krbCCache, krbConfig, client.DisablePAFXFAST(true))
	} else {
		krbClient = client.NewWithPassword(proxyUsername, proxyDomain, proxyPassword, krbConfig, client.DisablePAFXFAST(true))
		err = krbClient.Login()
	}
	if err != nil {
		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: Kerberos client error: %v\n", err)
		if readconfig.Config.Proxy.NtlmUser != "" && readconfig.Config.Proxy.NtlmPass != "" {

			log.Printf("INFO: Proxy: DoNegotiateProxyAuth: Try Negotiate / NTLM fallback: %v\n", err)
			err = DoNTLMProxyAuth(ctx, req, resp, "Negotiate")
			if err != nil {
				log.Printf("INFO: DoNegotiateProxyAuth: Negotiate / NTLM fallback failed: %v\n", err)
			}
		}
		return err
	}
	krbSPN := "HTTP/" + proxyFQDN
	spnegoClient := spnego.SPNEGOClient(krbClient, krbSPN)
	err = spnegoClient.AcquireCred()
	if err != nil {
		log.Println("INFO: Proxy: DoNegotiateProxyAuth: could not acquire spnego client credential: %v", err)
		return err
	}
	securityContext, err := spnegoClient.InitSecContext()
	if err != nil {
		log.Println("INFO: Proxy: DoNegotiateProxyAuth: could not initialize security context: %v", err)
		return err
	}
	negoAuth, err := securityContext.Marshal()
	if err != nil {
		log.Println("INFO: Proxy: DoNegotiateProxyAuth: %v\n", krberror.Errorf(err, krberror.EncodingError, "could not marshal SPNEGO"))
		return err
	}

	// fmt.Println(negoAuth)
	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString([]byte(negoAuth))))
	negoResp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: RoundTrip error(should not happen!): %v\n", err)
		if negoResp == nil {
			log.Printf("INFO: Proxy: DoNegotiateProxyAuth: no ntlmresp RoundTrip error: %v\n", err)
			return err
		} else if negoResp.StatusCode != http.StatusProxyAuthRequired {
			log.Printf("INFO: Proxy: DoNegotiateProxyAuth: RoundTrip error: %v\n", err)
			return err
		}
	}
	if negoResp.StatusCode == http.StatusProxyAuthRequired {
		// need really a loop, but unlikely to happen in real life
		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: Auth next %s\n", negoResp.Header.Get("Proxy-Authenticate"))
		challenge := strings.Split(negoResp.Header.Get("Proxy-Authenticate"), " ")
		if len(challenge) < 2 {
			log.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> The proxy did not return an negotiate challenge, got: '%s'\n", negoResp.Header.Get("Proxy-Authenticate"))
			return errors.New("no Negotiate challenge received")
		}
		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> negotiate challenge: '%s'\n", challenge[1])
		challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
		if err != nil {
			log.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> Could not base64 decode the NTLM challenge: %s\n", err)
			return err
		}
		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> negotiate authorizatio '%s'\n", base64.StdEncoding.EncodeToString(challengeMessage))
		//	authenticateMessage, err := nego.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
		//	if err != nil {
		//		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> Could not process the negotiate challenge: %s\n", err)
		//		return err
		//	}
		//	log.Printf("INFO: Proxy: DoNegotiateProxyAuth: ntlm> negotiate authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
		//	r.Header.Del("Proxy-Authorization")
		//	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
		//	negoResp, err = ctx.Prx.Rt.RoundTrip(r)
		return errors.New("additional negotiate reound required")
		//	} else if negoResp.StatusCode != http.StatusOK {
		//		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: Failed %d\n",negoResp.StatusCode)
		//		return errors.New("no negotiate OK received")
	}
	for k, v := range resp.Header {
		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: response header: %s=%s\n", k, v)
	}

	// Replace original response
	resp.StatusCode = negoResp.StatusCode
	resp.Status = negoResp.Status
	for k, _ := range resp.Header {
		resp.Header.Del(k)
		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: delete header %s\n", k)
	}
	for k, v := range negoResp.Header {
		for i := 0; i < len(v); i++ {
			resp.Header.Add(k, v[i])
		}
		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: add header %s=%s\n", k, v)
	}
	if negoResp.Body != http.NoBody {
		resp.Body = negoResp.Body
	} else {
		resp.Body = http.NoBody
	}
	resp.ContentLength = negoResp.ContentLength
	resp.TLS = negoResp.TLS
	copy(resp.TransferEncoding, negoResp.TransferEncoding)
	log.Printf("INFO: Proxy: DoNegotiateProxyAuth: Auth done\n")
	return nil
}
