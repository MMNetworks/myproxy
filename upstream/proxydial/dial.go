// Package proxydial handles dial via proxy
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

// PrxDial is a dial function for TLS connection using CONNECT method
// Input:
//
//	session context
//	network
//	address
//
// Output:
//
//	network connection
//
// This works as no response body is expected from the proxy
func PrxDial(ctx *httpproxy.Context, network, address string) (net.Conn, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var err error
	var host string
	var conn net.Conn

	proxy := ctx.UpstreamProxy

	logging.Printf("DEBUG", "PrxDial: SessionID:%d Connect to %s:%s via proxy %s\n", ctx.SessionNo, network, address, proxy)
	if httpproxy.HasPort.MatchString(address) {
		ipos := strings.LastIndex(address, ":")
		if ipos > 0 {
			host = address[0:ipos]
		}
	} else {
		host = address
	}

	if ctx.Req == nil {
		logging.Printf("ERROR", "PrxDial: SessionID:%d Received empty context request\n", ctx.SessionNo)
		return nil, errors.New("empty context request")
	}
	// Only use PrxdDial for Connect method
	tM := httpproxy.CleanUntrustedString(ctx, "Method", ctx.Req.Method)
	if ctx.ConnectReq == nil && tM != "CONNECT" {
		logging.Printf("ERROR", "PrxDial: SessionID:%d Received empty connect request\n", ctx.SessionNo)
		return nil, errors.New("empty request to proxy")
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
		_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\n", address)
		if err != nil {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Error writing to proxy connection %v %v\n", ctx.SessionNo, c2s(conn), err)
			return nil, err
		}
		_, err = fmt.Fprintf(conn, "Host: %s\r\n", host)
		if err != nil {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Error writing to proxy connection %v %v\n", ctx.SessionNo, c2s(conn), err)
			return nil, err
		}
		_, err = fmt.Fprintf(conn, "Proxy-Connection: Keep-Alive\r\n")
		if err != nil {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Error writing to proxy connection %v %v\n", ctx.SessionNo, c2s(conn), err)
			return nil, err
		}
		for k, v := range req.Header {
			tK := httpproxy.CleanUntrustedString(ctx, "Header key", k)
			if tK != "Host" && tK != "Proxy-Connection" {
				for i := 0; i < len(v); i++ {
					tV := httpproxy.CleanUntrustedString(ctx, "Header Value", v[i])
					_, err = fmt.Fprintf(conn, "%s: %s\r\n", tK, tV)
					if err != nil {
						logging.Printf("ERROR", "PrxDial: SessionID:%d Error writing to proxy connection %v %v\n", ctx.SessionNo, c2s(conn), err)
						return nil, err
					}
					logging.Printf("DEBUG", "PrxDial: SessionID:%d Add clean original header to proxy connection: %s=%s\n", ctx.SessionNo, tK, tV)
				}
			}
		}
		_, err = fmt.Fprintf(conn, "\r\n")
		if err != nil {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Error writing to proxy connection %v %v\n", ctx.SessionNo, c2s(conn), err)
			return nil, err
		}

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Error reading response from proxy: %v\n", ctx.SessionNo, err)
			return nil, err
		}
		ctx.AccessLog.Status = httpproxy.CleanUntrustedString(ctx, "Status", resp.Status)
		if resp.StatusCode == http.StatusProxyAuthRequired {
			_, err = io.ReadAll(resp.Body)
			if err != nil {
				logging.Printf("ERROR", "PrxDial: SessionID:%d Could not read response body from response: %v\n", ctx.SessionNo, err)
				return nil, err
			}

			defer func() { _ = resp.Body.Close() }()
			req.Header.Add("Proxy-Connection", "Keep-Alive")
			authenticate.DoProxyAuth(ctx, req, resp)
		}

		ctx.AccessLog.Status = httpproxy.CleanUntrustedString(ctx, "Status", resp.Status)
		ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
		ctx.AccessLog.DestinationIP = ""
		if resp.StatusCode != http.StatusOK {
			logging.Printf("ERROR", "PrxDial: SessionID:%d Failed to connect to %s via proxy %s. Response status: %s\n", ctx.SessionNo, address, proxy, ctx.AccessLog.Status)
			return nil, errors.New("CONNECT tunnel failed, response " + strconv.Itoa(resp.StatusCode))
		}
	}
	return conn, nil
}
