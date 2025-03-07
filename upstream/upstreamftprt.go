package upstream

import (
	"bufio"
	"fmt"
	"io"
	"myproxy/http-proxy"
	"myproxy/logging"
	"myproxy/readconfig"
	"myproxy/upstream/authenticate"
	"net"
	"net/http"
	"time"
	// "os"
	// "github.com/yassinebenaid/godump"
)

func c2s(conn net.Conn) string {
	return fmt.Sprintf("%s->%s", conn.LocalAddr(), conn.RemoteAddr())
}

type FtpRoundTripper struct {
	GetContext func() *httpproxy.Context
}

// Dial for TLS connection using CONNECT method
func (fR *FtpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var timeOut time.Duration = time.Duration(readconfig.Config.Connection.Timeout)
	var keepAlive time.Duration = time.Duration(readconfig.Config.Connection.Keepalive)
	var err error
	var conn net.Conn
	var resp *http.Response

	ctx := fR.GetContext()
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(),ctx.SessionNo)

	proxy := ctx.UpstreamProxy

	if proxy == "" {
		logging.Printf("DEBUG", "FtpRoundTrip: SessionID:%d proxy not set\n", ctx.SessionNo)
	} else {
		newDial := net.Dialer{
			Timeout:   timeOut * time.Second, // Set the timeout duration
			KeepAlive: keepAlive * time.Second,
		}
		conn, err = newDial.Dial("tcp", proxy)
		logging.Printf("DEBUG", "FtpRoundTrip: SessionID:%d After Dial: %v\n", ctx.SessionNo, c2s(conn))
		ctx.AccessLog.UpstreamProxyIP = conn.RemoteAddr().String()
		ctx.AccessLog.DestinationIP = ""
		// godump.Dump(ctx.Prx.Rt)
		if err != nil {
			logging.Printf("ERROR", "FtpRoundTripper: SessionID:%d Error connecting to proxy: %s %v\n", ctx.SessionNo, proxy, err)
			return nil, err
		}
		host := req.URL.Host
		if !httpproxy.HasPort.MatchString(host) {
			host += ":21"
		}
		fmt.Fprintf(conn, "%s %s HTTP/1.1\r\n", req.Method, req.URL.String())
		fmt.Fprintf(conn, "Host: %s\r\n", host)
		fmt.Fprintf(conn, "Proxy-Connection: Keep-Alive\r\n")
		for k, v := range req.Header {
			if k != "Host" && k != "Proxy-Connection" {
				fmt.Fprintf(conn, "%s: %s\r\n", k, v)
				logging.Printf("DEBUG", "FtpRoundTripper: SessionID:%d add header %s=%s\n", ctx.SessionNo, k, v)
			}
		}
		fmt.Fprintf(conn, "\r\n")

		resp, err = http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			logging.Printf("ERROR", "FtpRoundTripper: SessionID:%d Error reading response from proxy: %v\n", ctx.SessionNo, err)
			return nil, err
		}
		if resp.StatusCode == http.StatusProxyAuthRequired {
			_, err = io.ReadAll(resp.Body)
			if err != nil {
				logging.Printf("ERROR", "FtpRoundTripper: SessionID:%d Could not read response body from response: %v\n", ctx.SessionNo, err)
				return nil, err
			}
			defer resp.Body.Close()
			// fake http for RoundTrip to not throw an error, but return hesder.
			req.Header.Add("Proxy-Connection", "Keep-Alive")
			authenticate.DoProxyAuth(ctx, req, resp)
		}

		if resp.StatusCode != http.StatusOK {
			logging.Printf("ERROR", "FtpRoundTripper: SessionID:%d Failed to connect to proxy response status: %s\n", ctx.SessionNo, resp.Status)
		}
	}

	return resp, nil
}
