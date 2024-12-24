//go:build windows

package authenticate

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"encoding/base64"
        "github.com/alexbrainman/sspi/ntlm"
        "github.com/alexbrainman/sspi/negotiate"
	"io"
	"myproxy/http-proxy"
	"myproxy/readconfig"
	"strings"
	// "github.com/yassinebenaid/godump"
)

func DoNTLMProxyAuth(ctx *httpproxy.Context, req *http.Request, resp *http.Response, auth string) error {
	// NTLM Step 1: Send Negotiate Message
	sspiCred, err := ntlm.AcquireCurrentUserCredentials()
   	if err != nil {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: could not acquire spnego client credential: %v\n", err)
          	return err
    	}
    	defer sspiCred.Release()

	securityContext, ntlmToken, err := ntlm.NewClientContext(sspiCred)
	if err != nil {
        	log.Printf("INFO: Proxy: DoNTLMProxyAuth: Failed to initialize security context: %v\n", err)
        	return err
	}
	defer securityContext.Release()

	req.Header.Add("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(ntlmToken)))
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
	log.Printf("INFO: Proxy: DoNTLMProxyAuth: ntlm> Processing NTLM challenge\n")
	authenticateMessage, err :=  securityContext.Update(challengeMessage)
	if err != nil {
		log.Printf("INFO: Proxy: DoNTLMProxyAuth: ntlm> Could not process the NTLM challenge: %s\n", err)
		return err
	}
	defer securityContext.Release()
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
       var r = req
       var proxyFQDN string

        proxy := ctx.UpstreamProxy
	
        log.Printf("INFO: Proxy: DoNegotiateProxyAuth: proxy: %s\n", proxy)
        ipos := strings.Index(proxy, ":")
        if ipos > 0 {
                proxyFQDN = proxy[0:ipos]
        } else {
                proxyFQDN = proxy
        }

        proxyDomain := readconfig.Config.Proxy.KerberosDomain

	sspiCred, err := negotiate.AcquireCurrentUserCredentials()
   	if err != nil {
		log.Printf("INFO: Proxy: DoNegotiateProxyAuth: could not acquire spnego client credential: %v\n", err)
          	return err
    	}
    	defer sspiCred.Release()

	servicePrincipalName := "HTTP/" + proxyFQDN + "@" + proxyDomain
        log.Printf("INFO: Proxy: DoNegotiateProxyAuth: serviceprincipalname: %s\n", servicePrincipalName)
	securityContext, negoToken, err := negotiate.NewClientContext(sspiCred,servicePrincipalName)
	if err != nil {
        	fmt.Printf("INFO: Proxy: DoNegotiateProxyAuth: Failed to initialize security context: %v\n", err)
        	return err
	}
	defer securityContext.Release()

	r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(negoToken)))
        negoResp, err := ctx.Prx.Rt.RoundTrip(r)
        if err != nil {
                log.Printf("INFO: Proxy: DoNegotiateProxyAuth: RoundTrip error(should not happen!): %v\n", err)
                if negoResp == nil {
                        log.Printf("INFO: Proxy: DoNegotiateProxyAuth: no negoresp RoundTrip error: %v\n", err)
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
                        log.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> Could not base64 decode the Negotiate challenge: %s\n", err)
                        return err
                }
                log.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> negotiate authorization '%s'\n", base64.StdEncoding.EncodeToString(challengeMessage))
                //      authenticateMessage, err := nego.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, false)
                //      if err != nil {
                //              log.Printf("INFO: Proxy: DoNegotiateProxyAuth: nego> Could not process the negotiate challenge: %s\n", err)
                //              return err
                //      }
                //      log.Printf("INFO: Proxy: DoNegotiateProxyAuth: ntlm> negotiate authorization: '%s'\n", base64.StdEncoding.EncodeToString(authenticateMessage))
                //      r.Header.Del("Proxy-Authorization")
                //      r.Header.Add("Proxy-Authorization", fmt.Sprintf("Negotiate %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
                //      negoResp, err = ctx.Prx.Rt.RoundTrip(r)
                return errors.New("additional negotiate round required")
                //      } else if negoResp.StatusCode != http.StatusOK {
                //              log.Printf("INFO: Proxy: DoNegotiateProxyAuth: Failed %d\n",negoResp.StatusCode)
                //              return errors.New("no negotiate OK received")
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

