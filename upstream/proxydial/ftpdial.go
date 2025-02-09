package proxydial

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/readconfig"
	"myproxy/upstream/authenticate"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	// "os"
	// "github.com/yassinebenaid/godump"
)

// Dial for TLS connection using CONNECT method
func FtpPrxDial(ctx *httpproxy.Context, network, address string) (net.Conn, error) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	var timeOut time.Duration = time.Duration(readconfig.Config.Connection.Timeout)
	var keepAlive time.Duration = time.Duration(readconfig.Config.Connection.Keepalive)
	var err error
	var host string
	var buf []byte  
	var conn net.Conn

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "FtpPrxDial: %s %s %s\n", network, address, proxy)
	ipos := strings.Index(address, ":")
	if ipos > 0 {
		host = address[0:ipos]
	} else {
		host = address
	}

	if proxy == "" {
                logging.Printf("DEBUG", "FtpPrxDial: proxy not set\n")
	} else {
		newDial := net.Dialer{
			Timeout:   timeOut * time.Second, // Set the timeout duration
			KeepAlive: keepAlive * time.Second,
		}
		conn, err = newDial.Dial("tcp", proxy)
		logging.Printf("DEBUG", "FtpPrxDial: After Dial: %v\n", c2s(conn))
		// Overwrite upstream Proxy
		ctx.Prx.Rt = &http.Transport{TLSClientConfig: &tls.Config{},
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, err
			},
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				return conn, err
			},
		}
		// godump.Dump(ctx.Prx.Rt)
		req := ctx.Req
		if err != nil {
			logging.Printf("ERROR", "FtpPrxDial: Error connecting to proxy: %s %v\n", proxy, err)
			return nil, err
		}
		fmt.Fprintf(conn, "%s %s HTTP/1.1\r\n", req.Method,req.URL.String())
		fmt.Fprintf(conn, "Host: %s\r\n", host)
		fmt.Fprintf(conn, "Proxy-Connection: Keep-Alive\r\n")
		fmt.Fprintf(conn, "\r\n")

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			logging.Printf("ERROR", "FtpPrxDial: Error reading response from proxy: %v\n", err)
			return nil, err
		}
		ctx.AccessLog.Status = resp.Status
		if resp.StatusCode == http.StatusProxyAuthRequired {
			_, err = io.ReadAll(resp.Body)
			if err != nil {
				logging.Printf("ERROR", "FtpPrxDial: Could not read response body from response: %v\n", err)
				return nil, err
			}
			defer resp.Body.Close()
			// fake http for RoundTrip to not throw an error, but return hesder.
			req.URL, err = url.Parse("http://" + address)
			if err != nil {
				logging.Printf("ERROR", "FtpPrxDial: Creating request for proxy: %v\n", err)
				return nil, err
			}
			req.Header.Add("Proxy-Connection", "Keep-Alive")
			authenticate.DoProxyAuth(ctx, req, resp)
		}

		ctx.AccessLog.Status = resp.Status
		ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
		ctx.AccessLog.DestinationIP = ""
		if resp.StatusCode != http.StatusOK {
			logging.Printf("ERROR", "FtpPrxDial: Failed to connect to proxy response status: %s\n", resp.Status)
			return nil, errors.New("proxy connection failed, response " + strconv.Itoa(resp.StatusCode))
		}
		buf, err = io.ReadAll(resp.Body)
		_, err = conn.Write(buf)
		if err != nil {
			logging.Printf("ERROR", "FtpPrxDial: Error sending body: %v\n", err)
			return nil, err
		}
	}

	return conn, nil
}
