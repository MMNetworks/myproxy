package proxydial

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/upstream/authenticate"
	"net"
	"net/http"
	"strconv"
	"strings"
	// "os"
	// "github.com/yassinebenaid/godump"
)

func c2s(conn net.Conn) string {
	return fmt.Sprintf("%s->%s", conn.LocalAddr(), conn.RemoteAddr())
}

// Dial for TLS connection using CONNECT method
// This works as no response body is expected from the proxy
func PrxDial(ctx *httpproxy.Context, network, address string) (net.Conn, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var err error
	var host string
	var conn net.Conn

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "PrxDial: SessionID:%d Connect to %s:%s via proxy %s\n", ctx.SessionNo, network, address, proxy)
	ipos := strings.Index(address, ":")
	if ipos > 0 {
		host = address[0:ipos]
	} else {
		host = address
	}

	// Only use PrxdDial for Connect method
	if ctx.ConnectReq == nil && ctx.Req.Method != "CONNECT" {
		logging.Printf("ERROR", "PrxDial: SessionID:%d Received empty connect request\n", ctx.SessionNo)
		return nil, errors.New("Empty request to proxy")
	}
	if proxy != "" {
		var req *http.Request
		conn, err = httpproxy.NetDial(ctx, network, proxy)
		if err != nil {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Error dialing to proxy: %s %v\n", ctx.SessionNo, proxy, err)
			return nil, err
		}
		logging.Printf("DEBUG", "PrxDial: SessionID:%d Connection details after Dial: %v\n", ctx.SessionNo, c2s(conn))
		ctx.UpstreamConn = conn

		if ctx.ConnectReq != nil {
			req = ctx.ConnectReq
		} else {
			req = ctx.Req
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\n", address)
		fmt.Fprintf(conn, "Host: %s\r\n", host)
		fmt.Fprintf(conn, "Proxy-Connection: Keep-Alive\r\n")
		for k, v := range req.Header {
			if k != "Host" && k != "Proxy-Connection" {
				for i := 0; i < len(v); i++ {
					fmt.Fprintf(conn, "%s: %s\r\n", k, v[i])
				}
				logging.Printf("DEBUG", "PrxDial: SessionID:%d Add original header to proxy connection: %s=%s\n", ctx.SessionNo, k, v)
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

			req.Header.Add("Proxy-Connection", "Keep-Alive")
			authenticate.DoProxyAuth(ctx, req, resp)
		}

		ctx.AccessLog.Status = resp.Status
		ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
		ctx.AccessLog.DestinationIP = ""
		if resp.StatusCode != http.StatusOK {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Failed to connect to %s via proxy %s. Response status: %s\n", ctx.SessionNo, address, proxy, resp.Status)
			return nil, errors.New("CONNECT tunnel failed, response " + strconv.Itoa(resp.StatusCode))
		}
	}
	return conn, nil
}
