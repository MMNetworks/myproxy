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

func c2s(conn net.Conn) string {
	return fmt.Sprintf("%s->%s", conn.LocalAddr(), conn.RemoteAddr())
}

// Dial for TLS connection using CONNECT method
// This works as no response body is expected from the proxy
func PrxDial(ctx *httpproxy.Context, network, address string) (net.Conn, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(),ctx.SessionNo)
	var timeOut time.Duration = time.Duration(readconfig.Config.Connection.Timeout)
	var keepAlive time.Duration = time.Duration(readconfig.Config.Connection.Keepalive)
	var err error
	var host string
	var conn net.Conn

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "PrxDial: SessionID:%d %s %s %s\n", ctx.SessionNo, network, address, proxy)
	ipos := strings.Index(address, ":")
	if ipos > 0 {
		host = address[0:ipos]
	} else {
		host = address
	}

	if proxy != "" {
		newDial := net.Dialer{
			Timeout:   timeOut * time.Second, // Set the timeout duration
			KeepAlive: keepAlive * time.Second,
		}
		conn, err = newDial.Dial("tcp", proxy)
		logging.Printf("DEBUG", "PrxDial: SessionID:%d After Dial: %v\n", ctx.SessionNo, c2s(conn))
		// Overwrite upstream Proxy
		ctx.Prx.Rt = &http.Transport{TLSClientConfig: &tls.Config{},
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, err
			},
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				return conn, err
			},
		}
		// defer conn.Close()
		// godump.Dump(ctx.Prx.Rt)
		req := ctx.ConnectReq
		if err != nil {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Error connecting to proxy: %s %v\n", ctx.SessionNo, proxy, err)
			return nil, err
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\n", address)
		fmt.Fprintf(conn, "Host: %s\r\n", host)
		fmt.Fprintf(conn, "Proxy-Connection: Keep-Alive\r\n")
		for k, v := range req.Header {
			if k != "Host" && k != "Proxy-Connection" {
				fmt.Fprintf(conn, "%s: %s\r\n", k, v)
				logging.Printf("DEBUG", "PrxDial: SessionID:%d add header %s=%s\n", ctx.SessionNo, k, v)
			}
		}
		fmt.Fprintf(conn, "\r\n")

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Error reading response from proxy: %v\n", ctx.SessionNo, err)
			return nil, err
		}
		ctx.AccessLog.Status = resp.Status
		if resp.StatusCode == http.StatusProxyAuthRequired {
			_, err = io.ReadAll(resp.Body)
			if err != nil {
				logging.Printf("ERROR", "PrxDial: SessionID:%d Could not read response body from response: %v\n", ctx.SessionNo, err)
				return nil, err
			}
			defer resp.Body.Close()
			// fake http for RoundTrip to not throw an error, but return hesder.
			req.URL, err = url.Parse("http://" + address)
			if err != nil {
				logging.Printf("ERROR", "PrxDial: SessionID:%d Creating request for proxy: %v\n", ctx.SessionNo, err)
				return nil, err
			}
			req.Header.Add("Proxy-Connection", "Keep-Alive")
			authenticate.DoProxyAuth(ctx, req, resp)
		}

		ctx.AccessLog.Status = resp.Status
		ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
		ctx.AccessLog.DestinationIP = ""
		if resp.StatusCode != http.StatusOK {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Failed to connect to proxy response status: %s\n", ctx.SessionNo, resp.Status)
			return nil, errors.New("CONNECT tunnel failed, response " + strconv.Itoa(resp.StatusCode))
		}

	} else {
		newDial := net.Dialer{
			Timeout:   5 * time.Second, // Set the timeout duration
			KeepAlive: 5 * time.Second,
		}
		conn, err = newDial.Dial("tcp", address)
		if err != nil {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Error connecting to adress: %s error: %v\n", ctx.SessionNo, address, err)
			ctx.AccessLog.Status = "500 internal error"
			return nil, err
		}
		// defer conn.Close()
		ctx.AccessLog.UpstreamProxyIP = ""
		ctx.AccessLog.Status = "200 connected to " + conn.RemoteAddr().String()
		ctx.AccessLog.DestinationIP = conn.RemoteAddr().String()
	}
	return conn, nil
}
