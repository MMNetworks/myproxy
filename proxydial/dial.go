package proxydial

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"myproxy/authenticate"
	"myproxy/http-proxy"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	// "os"
	// "github.com/yassinebenaid/godump"
)

func c2s(conn net.Conn) string {
	return fmt.Sprintf("%s->%s", conn.LocalAddr(), conn.RemoteAddr())
}

// Dial for TLS connection using CONNECT method
func PrxDial(ctx *httpproxy.Context, network, address string) (net.Conn, error) {
	var err error
	var host string
	var conn net.Conn

	proxy := ctx.UpstreamProxy

	log.Printf("INFO: Proxy: PrxDial: %s %s %s\n", network, address, proxy)
	ipos := strings.Index(address, ":")
	if ipos > 0 {
		host = address[0:ipos]
	} else {
		host = address
	}

	if proxy != "" {
		conn, err = net.Dial("tcp", proxy)
		log.Printf("INFO: Proxy: PrxDial: After Dial: %v", c2s(conn))
		// Overwrite upstream Proxy
		ctx.Prx.Rt = &http.Transport{TLSClientConfig: &tls.Config{},
			Dial: func(network, addr string) (net.Conn, error) {
				log.Printf("INFO: Proxy: PrxDial: Transport Dial: %v", c2s(conn))
				return conn, err
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				log.Printf("INFO: Proxy: PrxDial: Transport DialContext: %v", c2s(conn))
				return conn, err
			},
		}
		// godump.Dump(ctx.Prx.Rt)
		req := ctx.ConnectReq
		if err != nil {
			log.Println("INFO: Proxy: PrxDial: Error connecting to proxy: %s %v", proxy, err)
			return nil, err
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\n", address)
		fmt.Fprintf(conn, "Host: %s\r\n", host)
		fmt.Fprintf(conn, "Proxy-Connection: Keep-Alive\r\n")
		fmt.Fprintf(conn, "\r\n")

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			log.Println("Error reading response from proxy:", err)
			return nil, err
		}

		// godump.Dump(req)
		if resp.StatusCode == http.StatusProxyAuthRequired {
			_, err = io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("INFO: Proxy: PrxDial: Could not read response body from response: %s", err)
				return nil, err
			}
			defer resp.Body.Close() 
			// fake http for RoundTrip to not through an error, but return hesder.
			req.URL, err = url.Parse("http://" + address)
			if err != nil {
				log.Println("INFO: Proxy: PrxDial: Creating request for proxy:", err)
				return nil, err
			}
			req.Header.Add("Proxy-Connection", "Keep-Alive")
			authenticate.DoProxyAuth(ctx, req, resp)
			// godump.Dump(resp)
		}

		if resp.StatusCode != http.StatusOK {
			log.Println("INFO: Proxy: PrxDial: Failed to connect to proxy:", resp.Status)
			return nil, errors.New("CONNECT tunnel failed, response " + strconv.Itoa(resp.StatusCode))
		}

	} else {
		conn, err = net.Dial("tcp", address)
		if err != nil {
			log.Println("INFO: Proxy: PrxDial: Error connecting to adress: %s %v", address, err)
			return nil, err
		}
	}
	return conn, nil
}
