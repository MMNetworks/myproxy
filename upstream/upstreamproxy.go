package upstream

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/darren/gpac"
	"io"
	"math/rand/v2"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/readconfig"
	"myproxy/upstream/authenticate"
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

func c2s(conn net.Conn) string {
	return fmt.Sprintf("%s->%s", conn.LocalAddr(), conn.RemoteAddr())
}

type ProxyRoundTripper struct {
	GetContext func() *httpproxy.Context
	proxyMutex sync.Mutex
}

func (pR *ProxyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := pR.GetContext()
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)

	pR.proxyMutex.Lock()
	defer pR.proxyMutex.Unlock()
	proxy := ctx.UpstreamProxy
	if proxy == "" {
		logging.Printf("ERROR", "proxyRoundTrip: SessionID:%d upstream proxy not set.\n", ctx.SessionNo)
	} else {
		logging.Printf("DEBUG", "proxyRoundTrip: SessionID:%d Request Method/Scheme: %s/%s\n", ctx.SessionNo, req.Method, req.URL.Scheme)
		if req.Method == "CONNECT" || req.URL.Scheme == "https" {
			var host string
			if req.Host == "" {
				host = req.URL.Host
			} else {
				host = req.Host
			}
			conn, err := proxydial.PrxDial(ctx, "tcp", host)
			// godump.Dump(ctx.Rt)
			if err != nil {
				logging.Printf("ERROR", "proxyRoundTripper: SessionID:%d Error connecting to proxy %s: %v\n", ctx.SessionNo, proxy, err)
				return nil, err
			}
			ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
			ctx.AccessLog.DestinationIP = ""

			logging.Printf("DEBUG", "proxyRoundTrip: SessionID:%d Connection details after PrxDial: %v\n", ctx.SessionNo, c2s(conn))
			if req.URL.Scheme == "https" {
				// TLS handshake to origin
				serverName := req.URL.Hostname()
				logging.Printf("DEBUG", "proxyRoundTrip: SessionID:%d Setup TLS connection to %s\n", ctx.SessionNo, serverName)
				tlsConf := ctx.TLSConfig
				if tlsConf == nil {
					tlsConf = &tls.Config{}
				}
				if tlsConf.ServerName == "" {
					clone := tlsConf.Clone()
					clone.ServerName = serverName
					tlsConf = clone
				}
				tlsConn := tls.Client(conn, tlsConf)
				if err := tlsConn.Handshake(); err != nil {
					logging.Printf("ERROR", "proxyRoundTripper: SessionID:%d TLS handshake to host %s via proxy %s failed: %v\n", ctx.SessionNo, serverName, proxy, err)
					return nil, err
				}
				// After this point, tlsConn is the underlying socket. Avoid closing conn twice.
				conn = tlsConn
				state := tlsConn.ConnectionState()
				ctx.AccessLog.Protocol = tls.VersionName(state.Version) + ":" + tls.CipherSuiteName(state.CipherSuite) + ":" + tlsConf.ServerName

			}
			// Could try http/2 for now http/1.1
			if err := req.Write(conn); err != nil {
				logging.Printf("ERROR", "proxyRoundTripper: SessionID:%d Error writing to proxy %s: %v\n", ctx.SessionNo, proxy, err)
				return nil, err
			}
			return http.ReadResponse(bufio.NewReader(conn), req)

		} else {
			conn, err := httpproxy.NetDial(ctx, "tcp", proxy)
			logging.Printf("DEBUG", "proxyRoundTrip: SessionID:%d Connection details after NetDial: %v\n", ctx.SessionNo, c2s(conn))
			ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
			ctx.AccessLog.DestinationIP = ""
			// godump.Dump(ctx.Rt)
			if err != nil {
				logging.Printf("ERROR", "proxyRoundTripper: SessionID:%d Error connecting to proxy %s: %v\n", ctx.SessionNo, proxy, err)
				return nil, err
			}
			if req.URL.Scheme == "ftp" {
				host := req.URL.Host
				if !httpproxy.HasPort.MatchString(host) {
					host += ":21"
				}
				fmt.Fprintf(conn, "%s %s HTTP/1.1\r\n", req.Method, req.URL.String())
				fmt.Fprintf(conn, "Host: %s\r\n", host)
				fmt.Fprintf(conn, "Proxy-Connection: Keep-Alive\r\n")
				for k, v := range req.Header {
					if k != "Host" && k != "Proxy-Connection" {
						for i := 0; i < len(v); i++ {
							fmt.Fprintf(conn, "%s: %s\r\n", k, v[i])
						}
						logging.Printf("DEBUG", "proxyRoundTripper: SessionID:%d Add original header to proxy connection: %s=%s\n", ctx.SessionNo, k, v)
					}
				}
				fmt.Fprintf(conn, "\r\n")
			} else {
				if err := req.WriteProxy(conn); err != nil {
					logging.Printf("ERROR", "proxyRoundTripper: SessionID:%d Error writing to proxy %s: %v\n", ctx.SessionNo, proxy, err)
					return nil, err
				}
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil {
				logging.Printf("ERROR", "proxyRoundTripper: SessionID:%d Error reading response from proxy %s: %v\n", ctx.SessionNo, proxy, err)
				return nil, err
			}

			ctx.AccessLog.Status = resp.Status
			if resp.StatusCode == http.StatusProxyAuthRequired {
				_, err = io.ReadAll(resp.Body)
				if err != nil {
					logging.Printf("ERROR", "proxyRoundTripper: SessionID:%d Could not read response body from proxy response: %v\n", ctx.SessionNo, err)
					return nil, err
				}
				defer resp.Body.Close()

				ctx.UpstreamConn = conn
				req.Header.Add("Proxy-Connection", "Keep-Alive")
				authenticate.DoProxyAuth(ctx, req, resp)
			}
			ctx.AccessLog.Status = resp.Status
			ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
			ctx.AccessLog.DestinationIP = ""
			return resp, nil

		}
	}
	return nil, nil
}

func SetProxy(ctx *httpproxy.Context) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)

	var err error
	var buf []byte
	var cacheTime time.Duration = 3600 * time.Second
	var transport *http.Transport
	var proxyFQDN string = ""
	var proxyPort string = "3128"
	logging.Printf("DEBUG", "SetProxy: SessionID:%d %s %s\n", ctx.SessionNo, ctx.Req.Method, ctx.Req.URL.Redacted())

	if readconfig.Config.PAC.Type != "" {
		if time.Now().Sub(timeNext) >= 0 {
			if readconfig.Config.PAC.Type == "URL" {
				logging.Printf("DEBUG", "SetProxy: SessionID:%d Use PAC URL %s\n", ctx.SessionNo, readconfig.Config.PAC.URL)
				var hclient http.Client
				if readconfig.Config.PAC.Proxy != "" {
					logging.Printf("DEBUG", "SetProxy: SessionID:%d Use PAC URL via proxy %s\n", ctx.SessionNo, readconfig.Config.PAC.Proxy)
					proxyURL, err := url.Parse(readconfig.Config.PAC.Proxy)
					if err != nil {
						logging.Printf("ERROR", "SetProxy: SessionID:%d Could not parse PAC file: %v\n", ctx.SessionNo, err)
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
					logging.Printf("DEBUG", "SetProxy: SessionID:%d PAC server response header: %s=%s\n", ctx.SessionNo, k, v)

				}
				Values := pResp.Header.Get("Cache-Control")
				_, err = io.ReadAll(pResp.Body)
				if err != nil {
					logging.Printf("ERROR", "SetProxy: SessionID:%d Could not parse PAC file: %v\n", ctx.SessionNo, err)
					return err
				}
				defer pResp.Body.Close()
				logging.Printf("DEBUG", "SetProxy: SessionID:%d Received Cache-Contro settingl: %s\n", ctx.SessionNo, Values)
				ipos1 := strings.Index(Values, "max-age=")
				ipos2 := strings.Index(Values, ",")
				if ipos1 > -1 {
					if ipos2 > ipos1 {
						cacheTime, err = time.ParseDuration(Values[ipos1+8:ipos2] + "s")
						if err != nil {
							logging.Printf("ERROR", "SetProxy: SessionID:%d Could not determine cache time: %v\n", ctx.SessionNo, err)
							return err
						}
					} else {
						cacheTime, err = time.ParseDuration(Values[ipos1+8:ipos2] + "s")
						if err != nil {
							logging.Printf("ERROR", "SetProxy: SessionID:%d Could not determine cache time: %v\n", ctx.SessionNo, err)
							return err
						}
					}
				} else {
					logging.Printf("ERROR", "SetProxy: SessionID:%d Could not determine cache time: max-age not send\n", ctx.SessionNo)
				}
				if readconfig.Config.PAC.CacheTime != 0 {
					cacheTime = time.Duration(readconfig.Config.PAC.CacheTime) * time.Second
				}
				timeNext = time.Now().Add(cacheTime)
				logging.Printf("INFO", "SetProxy: SessionID:%d Set PAC cache time to %s\n", ctx.SessionNo, cacheTime.String())
				pResp, err = hclient.Get(readconfig.Config.PAC.URL)
				if err != nil {
					logging.Printf("ERROR", "SetProxy: SessionID:%d Could not get PAC URL: %v\n", ctx.SessionNo, err)
					return err
				}
				buf, err = io.ReadAll(pResp.Body)
				if err != nil {
					logging.Printf("ERROR", "SetProxy: SessionID:%d Could not get PAC URL: %v\n", ctx.SessionNo, err)
					return err
				}
				defer pResp.Body.Close()
			} else if readconfig.Config.PAC.Type == "FILE" {
				logging.Printf("DEBUG", "SetProxy: SessionID:%d Use PAC file %s\n", ctx.SessionNo, readconfig.Config.PAC.File)
				buf, err = os.ReadFile(readconfig.Config.PAC.File)
				if err != nil {
					logging.Printf("ERROR", "SetProxy: SessionID:%d Could not read PAC file: %v\n", ctx.SessionNo, err)
					return err
				}
				if readconfig.Config.PAC.CacheTime != 0 {
					timeNext = time.Now().Add(time.Duration(readconfig.Config.PAC.CacheTime) * time.Second)
					cacheTime = time.Duration(readconfig.Config.PAC.CacheTime) * time.Second
				} else {
					timeNext = time.Now().Add(READ_WAIT)
					cacheTime = READ_WAIT
				}
				logging.Printf("INFO", "SetProxy: SessionID:%d Set PAC cache time to %s\n", ctx.SessionNo, cacheTime.String())
			}
			pac, err = gpac.New(string(buf))
			if err != nil {
				logging.Printf("ERROR", "SetProxy: SessionID:%d Could not load PAC data: %v\n", ctx.SessionNo, err)
				return err
			}
			logging.Printf("INFO", "SetProxy: SessionID:%d Next check for PAC data: %s\n", ctx.SessionNo, timeNext.Format(time.RFC850))
		}
		logging.Printf("DEBUG", "SetProxy: SessionID:%d PAC FindProxyForURL\n", ctx.SessionNo)
		proxyFrompac, err := pac.FindProxyForURL(ctx.Req.URL.String())
		if err != nil {
			logging.Printf("ERROR", "SetProxy: SessionID:%d Could not find proxy from PAC data: %v\n", ctx.SessionNo, err)
			return err
		}

		logging.Printf("DEBUG", "SetProxy: SessionID:%d Get proxy list from PAC ParseProxy call\n", ctx.SessionNo)
		ProxyList := gpac.ParseProxy(proxyFrompac)
		logging.Printf("DEBUG", "SetProxy: SessionID:%d Got proxy list of length %d\n", ctx.SessionNo, len(ProxyList))
		// Loop over proxy list
		if len(ProxyList) > 1 {
			proxyOKList := make([]string, len(ProxyList))
			var proxyOKCount int = -1
			for i, v := range ProxyList {
				logging.Printf("DEBUG", "SetProxy: SessionID:%d Proxy list index: %d type: %s address: %s\n", ctx.SessionNo, i+1, v.Type, v.Address)
				if strings.ToUpper(v.Type) == "DIRECT" {
					proxyOKCount = -1
				} else if strings.ToUpper(v.Type) != "PROXY" {
					logging.Printf("DEBUG", "SetProxy: SessionID:%d Unuspported Proxy type: %s\n", ctx.SessionNo, v.Type)
				} else {
					logging.Printf("DEBUG", "SetProxy: SessionID:%d Test connection to %s\n", ctx.SessionNo, v.Address)
					// test proxy port
					conn, err := httpproxy.NetDial(ctx, "tcp", v.Address)
					if err != nil {
						logging.Printf("ERROR", "SetProxy: SessionID: %d Dial error: %v\n", ctx.SessionNo, err)
						continue
					}
					conn.Close()
					logging.Printf("DEBUG", "SetProxy: SessionID:%d Add: %s to proxy list\n", ctx.SessionNo, v.Address)
					proxyOKCount++
					proxyOKList[proxyOKCount] = v.Address
				}
			}
			// randomize proxy from list
			if proxyOKCount >= 0 {
				logging.Printf("DEBUG", "SetProxy: SessionID:%d Count of working proxies: %d\n", ctx.SessionNo, proxyOKCount)
				randProxy := rand.IntN(proxyOKCount)
				logging.Printf("DEBUG", "SetProxy: SessionID:%d Chose proxy %d\n", ctx.SessionNo, randProxy)
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
			logging.Printf("DEBUG", "SetProxy: SessionID:%d Proxy list index: %d type: %s address: %s\n", ctx.SessionNo, 1, ProxyList[0].Type, ProxyList[0].Address)
			if strings.ToUpper(ProxyList[0].Type) == "DIRECT" {
				proxyFQDN = "DIRECT"
			} else if strings.ToUpper(ProxyList[0].Type) != "PROXY" {
				logging.Printf("DEBUG", "SetProxy: SessionID:%d Unuspported Proxy type: %s\n", ctx.SessionNo, ProxyList[0].Type)
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
	} else {
		proxyFQDN = "DIRECT"
	}
	if proxyFQDN != "" && strings.ToUpper(proxyFQDN) != "DIRECT" {
		proxyStr := "http://" + proxyFQDN + ":" + proxyPort
		logging.Printf("INFO", "SetProxy: SessionID:%d Setting upstream proxy to %s\n", ctx.SessionNo, proxyStr)
		// logging.Printf("DEBUG", "SetProxy: SessionID:%d URL Method/Scheme: %s/%s\n", ctx.SessionNo, ctx.Req.Method,ctx.Req.URL.Scheme)

		// Overwrite upstream Proxy
		ctx.Dial = proxydial.PrxDial
		ctx.UpstreamProxy = proxyFQDN + ":" + proxyPort

		// proxy RT to deal with https and http requests
		ctx.Rt = &ProxyRoundTripper{
			GetContext: func() *httpproxy.Context {
				return ctx
			},
		}
	} else {
		logging.Printf("INFO", "SetProxy: SessionID:%d Setting no upstream proxy\n", ctx.SessionNo)
		ctx.Dial = httpproxy.NetDial
		ctx.UpstreamProxy = ""
	}
	return nil
}
