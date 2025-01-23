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

func c2s(conn net.Conn) string {
	return fmt.Sprintf("%s->%s", conn.LocalAddr(), conn.RemoteAddr())
}

// Dial for TLS connection using CONNECT method
func PrxDial(ctx *httpproxy.Context, network, address string) (net.Conn, error) {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	var err error
	var host string
	var conn net.Conn

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "PrxDial: %s %s %s\n", network, address, proxy)
	ipos := strings.Index(address, ":")
	if ipos > 0 {
		host = address[0:ipos]
	} else {
		host = address
	}

	if proxy != "" {
		newDial := net.Dialer{
			Timeout:   5 * time.Second, // Set the timeout duration
			KeepAlive: 5 * time.Second,
		}
		conn, err = newDial.Dial("tcp", proxy)
		logging.Printf("DEBUG", "PrxDial: After Dial: %v\n", c2s(conn))
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
		req := ctx.ConnectReq
		if err != nil {
			logging.Printf("ERROR", "PrxDial: Error connecting to proxy: %s %v\n", proxy, err)
			return nil, err
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\n", address)
		fmt.Fprintf(conn, "Host: %s\r\n", host)
		fmt.Fprintf(conn, "Proxy-Connection: Keep-Alive\r\n")
		fmt.Fprintf(conn, "\r\n")

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			logging.Printf("ERROR", "PrxDial: Error reading response from proxy: %v\n", err)
			return nil, err
		}
		ctx.AccessLog.Status = resp.Status
		if resp.StatusCode == http.StatusProxyAuthRequired {
			_, err = io.ReadAll(resp.Body)
			if err != nil {
				logging.Printf("ERROR", "PrxDial: Could not read response body from response: %v\n", err)
				return nil, err
			}
			defer resp.Body.Close()
			// fake http for RoundTrip to not through an error, but return hesder.
			req.URL, err = url.Parse("http://" + address)
			if err != nil {
				logging.Printf("ERROR", "PrxDial: Creating request for proxy: %v\n", err)
				return nil, err
			}
			req.Header.Add("Proxy-Connection", "Keep-Alive")
			authenticate.DoProxyAuth(ctx, req, resp)
		}

		ctx.AccessLog.Status = resp.Status
		ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
		ctx.AccessLog.DestinationIP = ""
		if resp.StatusCode != http.StatusOK {
			logging.Printf("ERROR", "PrxDial: Failed to connect to proxy response status: %s\n", resp.Status)
			return nil, errors.New("CONNECT tunnel failed, response " + strconv.Itoa(resp.StatusCode))
		}

	} else {
		newDial := net.Dialer{
			Timeout:   5 * time.Second, // Set the timeout duration
			KeepAlive: 5 * time.Second,
		}
		conn, err = newDial.Dial("tcp", address)
		if err != nil {
			logging.Printf("ERROR", "PrxDial: Error connecting to adress: %s error: %v\n", address, err)
			ctx.AccessLog.Status = "500 internal error"
			return nil, err
		}
		ctx.AccessLog.UpstreamProxyIP = ""
		ctx.AccessLog.Status = "200 connected to " + conn.RemoteAddr().String()
		ctx.AccessLog.DestinationIP = conn.RemoteAddr().String()
	}
	return conn, nil
}
