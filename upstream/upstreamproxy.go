package upstream

import (
	"context"
	"crypto/tls"
	"github.com/darren/gpac"
	"io"
	"math/rand/v2"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/readconfig"
	"myproxy/upstream/proxydial"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	// "github.com/yassinebenaid/godump"
)

// reread pac file wait
const READ_WAIT time.Duration = 600 * time.Second

var timeNext time.Time = time.Now()
var pac *gpac.Parser

func SetProxy(ctx *httpproxy.Context) error {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())

	var timeOut time.Duration = time.Duration(readconfig.Config.Connection.Timeout)
	var keepAlive time.Duration = time.Duration(readconfig.Config.Connection.Keepalive)
	var err error
	var buf []byte
	var transport *http.Transport
	logging.Printf("DEBUG", "SetProxy: %s %s\n", ctx.Req.Method, ctx.Req.URL.Redacted())

	if time.Now().Sub(timeNext) >= 0 {
		if readconfig.Config.PAC.Type == "URL" {
			logging.Printf("DEBUG", "SetProxy: use PAC URL: %s\n", readconfig.Config.PAC.URL)
			var hclient http.Client
			if readconfig.Config.PAC.Proxy != "" {
				logging.Printf("DEBUG", "SetProxy: use PAC URL via proxy: %s\n", readconfig.Config.PAC.Proxy)
				proxyURL, err := url.Parse(readconfig.Config.PAC.Proxy)
				if err != nil {
					logging.Printf("ERROR", "SetProxy: could not parse PAC file: %v\n", err)
					return err
				}
				transport = &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				}
			} else {
				transport = &http.Transport{}
			}
			//adding the Transport object to the http Client
			hclient = http.Client{
				Transport: transport,
			}
			pResp, err := hclient.Head(readconfig.Config.PAC.URL)
			for k, v := range pResp.Header {
				logging.Printf("DEBUG", "SetProxy: response header: %s=%s\n", k, v)

			}
			Values := pResp.Header.Get("Cache-Control")
			_, err = io.ReadAll(pResp.Body)
			if err != nil {
				logging.Printf("ERROR", "SetProxy: could not parse PAC file: %v\n", err)
				return err
			}
			defer pResp.Body.Close()
			logging.Printf("DEBUG", "SetProxy: Cache-Control: %s\n", Values)
			ipos1 := strings.Index(Values, "max-age=")
			ipos2 := strings.Index(Values, ",")
			var cacheTime time.Duration
			if ipos2 > ipos1 {
				cacheTime, err = time.ParseDuration(Values[ipos1+8:ipos2] + "s")
				if err != nil {
					logging.Printf("ERROR", "SetProxy: could not determine cache time: %v\n", err)
					return err
				}
			} else {
				cacheTime, err = time.ParseDuration(Values[ipos1+8:ipos2] + "s")
				if err != nil {
					logging.Printf("ERROR", "SetProxy: could not determine cache time: %v\n", err)
					return err
				}
			}
			if readconfig.Config.PAC.CacheTime != 0 {
				timeNext = time.Now().Add(time.Duration(readconfig.Config.PAC.CacheTime) * time.Second)
			} else {
				timeNext = time.Now().Add(cacheTime)
			}

			pResp, err = hclient.Get(readconfig.Config.PAC.URL)
			if err != nil {
				logging.Printf("ERROR", "SetProxy: could not get PAC URL: %v\n", err)
				return err
			}
			buf, err = io.ReadAll(pResp.Body)
			if err != nil {
				logging.Printf("ERROR", "SetProxy: could not get PAC URL: %v\n", err)
				return err
			}
			defer pResp.Body.Close()
		} else if readconfig.Config.PAC.Type == "FILE" {
			logging.Printf("DEBUG", "SetProxy: use PAC file: %s\n", readconfig.Config.PAC.File)
			buf, err = os.ReadFile(readconfig.Config.PAC.File)
			if err != nil {
				logging.Printf("ERROR", "SetProxy: could not read PAC file: %v\n", err)
				return err
			}
			if readconfig.Config.PAC.CacheTime != 0 {
				timeNext = time.Now().Add(time.Duration(readconfig.Config.PAC.CacheTime) * time.Second)
			} else {
				timeNext = time.Now().Add(READ_WAIT)
			}
		}
		pac, err = gpac.New(string(buf))
		if err != nil {
			logging.Printf("ERROR", "SetProxy: could not load PAC data: %v\n", err)
			return err
		}
		logging.Printf("DEBUG", "SetProxy: Next check for PAC data: %s\n", timeNext.Format(time.RFC850))
	}

	logging.Printf("DEBUG", "SetProxy: PAC FindProxyForURL\n")
	proxyFrompac, err := pac.FindProxyForURL(ctx.Req.URL.String())
	if err != nil {
		logging.Printf("ERROR", "SetProxy: could not find proxy from PAC data: %v\n", err)
		return err
	}

	logging.Printf("DEBUG", "SetProxy: PAC ParseProxy\n")
	ProxyList := gpac.ParseProxy(proxyFrompac)
	logging.Printf("DEBUG", "SetProxy: PAC got proxy list\n")
	proxyFQDN := ""
	proxyPort := "3128"
	// Loop over proxy list
	if len(ProxyList) > 1 {
		proxyOKList := make([]string, len(ProxyList))
		var proxyOKCount int = -1
		for i, v := range ProxyList {
			logging.Printf("DEBUG", "SetProxy: Index: %d, Type: %s Address: %s\n", i+1, v.Type, v.Address)
			if strings.ToUpper(v.Type) == "DIRECT" {
				logging.Printf("DEBUG", "SetProxy: DIRECT\n")
				proxyOKCount = -1
			} else if strings.ToUpper(v.Type) != "PROXY" {
				logging.Printf("DEBUG", "SetProxy: Unuspported Proxy type: %s\n", v.Type)
			} else {
				logging.Printf("DEBUG", "SetProxy: Dial %s\n", v.Address)
				// test proxy port
				connectCheck := net.Dialer{
					Timeout:   timeOut * time.Second, // Set the timeout duration
					KeepAlive: keepAlive * time.Second,
				}
				conn, err := connectCheck.Dial("tcp", v.Address)
				if err != nil {
					logging.Printf("ERROR", "SetProxy: Dial error: %v\n", err)
					continue
				}
				defer conn.Close()
				logging.Printf("DEBUG", "SetProxy: Add: %s to proxy list\n", v.Address)
				proxyOKCount++
				proxyOKList[proxyOKCount] = v.Address
			}
		}
		// randomize proxy from list
		if proxyOKCount >= 0 {
			logging.Printf("DEBUG", "SetProxy: OK Count: %d\n", proxyOKCount)
			randProxy := rand.IntN(proxyOKCount)
			logging.Printf("DEBUG", "SetProxy: randCount: %d\n", randProxy)
			ipos := strings.Index(proxyOKList[randProxy], ":")
			if ipos > 0 {
				proxyFQDN = proxyOKList[randProxy][0:ipos]
				proxyPort = proxyOKList[randProxy][ipos+1:]
			} else {
				proxyFQDN = proxyOKList[randProxy]
			}
		} else {
			// fallback to direct
			proxyFQDN = "DIRECT"
		}
	} else {
		logging.Printf("DEBUG", "SetProxy: Index: %d, Type: %s Address: %s\n", 1, ProxyList[0].Type, ProxyList[0].Address)
		if strings.ToUpper(ProxyList[0].Type) == "DIRECT" {
			proxyFQDN = "DIRECT"
		} else if strings.ToUpper(ProxyList[0].Type) != "PROXY" {
			logging.Printf("DEBUG", "SetProxy: Unuspported Proxy type: %s\n", ProxyList[0].Type)
		} else {
			ipos := strings.Index(ProxyList[0].Address, ":")
			if ipos > 0 {
				proxyFQDN = ProxyList[0].Address[0:ipos]
				proxyPort = ProxyList[0].Address[ipos+1:]
			} else {
				proxyFQDN = ProxyList[0].Address
			}
		}
	}
	if proxyFQDN != "" && strings.ToUpper(proxyFQDN) != "DIRECT" {
		proxyStr := "http://" + proxyFQDN + ":" + proxyPort
		logging.Printf("DEBUG", "SetProxy: proxySTR: %s\n", proxyStr)
		proxyURL, err := url.Parse(proxyStr)
		if err != nil {
			logging.Printf("ERROR", "SetProxy: Could not parse proxy URL %s\n", proxyStr)
			return err
		}
		logging.Printf("DEBUG", "SetProxy: URL Scheme: %s\n", ctx.Req.URL.Scheme)
		// Overwrite upstream Proxy
		ctx.Prx.Rt = &http.Transport{TLSClientConfig: &tls.Config{},
			Proxy: http.ProxyURL(proxyURL),
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{
					Timeout:   timeOut * time.Second,
					KeepAlive: keepAlive * time.Second,
				}).DialContext(dctx, network, addr)
				if err != nil {
					return nil, err
				}
				ctx.AccessLog.DestinationIP = ""
				ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
				return conn, nil
			},
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{
					Timeout:   timeOut * time.Second,
					KeepAlive: keepAlive * time.Second,
				}).Dial(network, addr)
				if err != nil {
					return nil, err
				}
				ctx.AccessLog.DestinationIP = ""
				ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
				return conn, nil
			},
		}
		if strings.ToUpper(ctx.Req.URL.Scheme) == "FTP" {
			ctx.Prx.Rt = &FtpRoundTripper{
				GetContext: func() *httpproxy.Context {
					return ctx
				},
			}
		}
		// Use upstream Proxy for CONNECT
		ctx.Prx.Dial = proxydial.PrxDial
		ctx.UpstreamProxy = proxyFQDN + ":" + proxyPort
	} else {
		logging.Printf("DEBUG", "SetProxy: proxySTR: DIRECT\n")
		ctx.Prx.Rt = &http.Transport{TLSClientConfig: &tls.Config{},
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{
					Timeout:   timeOut * time.Second,
					KeepAlive: keepAlive * time.Second,
				}).DialContext(dctx, network, addr)
				if err != nil {
					return nil, err
				}
				ctx.AccessLog.DestinationIP = conn.RemoteAddr().String()
				return conn, nil
			},
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{
					Timeout:   timeOut * time.Second,
					KeepAlive: keepAlive * time.Second,
				}).Dial(network, addr)
				if err != nil {
					return nil, err
				}
				ctx.AccessLog.DestinationIP = conn.RemoteAddr().String()
				return conn, nil
			},
		}
		ctx.Prx.Dial = httpproxy.NetDial
		ctx.UpstreamProxy = ""
	}
	return nil
}
