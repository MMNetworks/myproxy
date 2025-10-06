package httpproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/secsy/goftp"
	//        "github.com/dutchcoders/go-clamd"
	"errors"
	"io"
	"io/ioutil"
	"myproxy/logging"
	"myproxy/protocol"
	"myproxy/readconfig"
	"myproxy/viruscheck"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Context keeps context of each proxy request.
type Context struct {
	// Pointer of Proxy struct handled this context.
	// It's using internally. Don't change in Context struct!
	Prx *Proxy

	// Session number of this context obtained from Proxy struct.
	SessionNo int64

	// Sub session number of processing remote connection.
	SubSessionNo int64

	// Session read timeout e.g. for Websocket connections
	ReadTimeout int

	// Original Proxy Roundtripper
	// RoundTripper interface to obtain remote response.
	// changes depening on upstream proxy
	Rt http.RoundTripper

	// Original Proxy Dial
	// Dial interface to connect to remote host.
	// changes depening on upstream proxy
	Dial func(ctx *Context, network string, address string) (net.Conn, error)

	//  Request / Response connection information for Websocket Connection
	WebsocketState *protocol.WSStruct

	// Request / Response connection information for Wireshark
	TCPState *protocol.TCPStruct

	// Original Proxy request.
	// It's using internally. Don't change in Context struct!
	Req *http.Request

	// Upstream proxy response
	// It's using internally. Don't change in Context struct!
	Resp *http.Response

	// Original Proxy request, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectReq *http.Request

	// Action of after the CONNECT, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectAction ConnectAction

	// Remote host, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectHost string

	// Upstream Proxy host
	// It's using internally. Don't change in Context struct!
	UpstreamProxy string

	// Upstream Proxy host
	// It's using internally. Don't change in Context struct!
	UpstreamConn net.Conn

	// TLS Break flag
	// It's using internally. Don't change in Context struct!
	TLSBreak bool

	// TLS Config
	// It's using internally. Don't change in Context struct!
	TLSConfig *tls.Config

	// AccessLog record
	// It's using internally. Don't change in Context struct!
	AccessLog logging.AccessLogRecord

	// User data to use free.
	UserData interface{}

	hijTLSConn   *tls.Conn
	hijTLSReader *bufio.Reader
}

func (ctx *Context) GetTCPState() *protocol.TCPStruct {
	return ctx.TCPState
}

func (ctx *Context) onAccept(w http.ResponseWriter, r *http.Request) bool {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Accept", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnAccept(ctx, w, r)
}

func (ctx *Context) onAuth(authType string, user string, pass string) bool {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Auth", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnAuth(ctx, authType, user, pass)
}

func (ctx *Context) onConnect(host string) (ConnectAction ConnectAction,
	newHost string) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Connect", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnConnect(ctx, host)
}

func (ctx *Context) onRequest(req *http.Request) (resp *http.Response) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Request", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnRequest(ctx, req)
}

func (ctx *Context) onResponse(req *http.Request, resp *http.Response) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Response", ErrPanic, err)
		}
	}()
	ctx.Prx.OnResponse(ctx, req, resp)
}

func (ctx *Context) doError(where string, err *Error, opErr error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	if ctx.Prx.OnError == nil {
		return
	}
	ctx.Prx.OnError(ctx, where, err, opErr)
}

func (ctx *Context) doAccept(w http.ResponseWriter, r *http.Request) bool {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	ctx.Req = r
	if !r.ProtoAtLeast(1, 0) || r.ProtoAtLeast(2, 0) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Accept", ErrNotSupportHTTPVer, nil)
		return true
	}
	if ctx.Prx.OnAccept != nil && ctx.onAccept(w, r) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		return true
	}
	return false
}

func (ctx *Context) doAuth(w http.ResponseWriter, r *http.Request) bool {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)

	if r.Method != "CONNECT" && !r.URL.IsAbs() {
		return false
	}
	if ctx.Prx.OnAuth == nil {
		return false
	}
	prxAuthType := ctx.Prx.AuthType
	if prxAuthType == "" {
		prxAuthType = "Basic"
	}
	unauthorized := false
	authParts := strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)
	if len(authParts) >= 2 {
		authType := authParts[0]
		authData := authParts[1]
		if prxAuthType == authType {
			unauthorized = true
			switch authType {
			case "Basic":
				userpassraw, err := base64.StdEncoding.DecodeString(authData)
				if err == nil {
					userpass := strings.SplitN(string(userpassraw), ":", 2)
					if len(userpass) >= 2 && ctx.onAuth(authType, userpass[0], userpass[1]) {
						return false
					}
				}
			default:
				unauthorized = false
			}
		}
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	respCode := 407
	respBody := "Proxy Authentication Required"
	if unauthorized {
		respBody += " [Unauthorized]"
	}
	err := ServeInMemory(w, respCode, map[string][]string{"Proxy-Authenticate": {prxAuthType}},
		[]byte(respBody))
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Auth", ErrResponseWrite, err)
	}
	return true
}

type ftpLogWriter struct {
	writer    io.Writer
	bytes     *bytesCounter
	sessionNo int64
}

type bytesCounter struct {
	totalBytesIN  int64
	totalBytesOUT int64
}

func (w ftpLogWriter) Write(p []byte) (n int, err error) {

	lines := bytes.Split(p, []byte("\n"))

	logString := string(p)
	for _, line := range lines {
		str := string(line)
		if str != "" {
			logging.Printf("DEBUG", "ftpLogWriter: SessionID:%d logstring: %s\n", w.sessionNo, str)
		}
	}
	sendIndex := strings.Index(logString, "sending command ")
	if sendIndex != -1 {
		w.bytes.totalBytesOUT += int64(len(logString[sendIndex+16:])) + int64(len(lines)-1)
	}
	gotIndex := strings.Index(logString, "got ")
	if gotIndex != -1 {
		w.bytes.totalBytesIN += int64(len(logString[gotIndex+4:])) + int64(len(lines)-1)
	}
	//      logging.Printf("DEBUG", "ftpLogWriter: SessionID:%d BytesIN: %d BytesOUT: %d\n", w.sessionNo, w.bytes.totalBytesIN, w.bytes.totalBytesOUT)
	return len(p), nil
}

// Function to convert bytes to readable size
func formatSize(bytes int64) string {
	const (
		kB = 1024
		MB = kB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= kB:
		return fmt.Sprintf("%.2f kB", float64(bytes)/kB)
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

func (ctx *Context) doFtpUpstream(w http.ResponseWriter, r *http.Request) (bool, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)

	proxy := ctx.UpstreamProxy

	if r.Body != nil {
		defer r.Body.Close()
	}

	if proxy == "" {
		logging.Printf("DEBUG", "doFtpUpstream: SessionID:%d upstream proxy not set\n", ctx.SessionNo)
		return true, nil
	}

	host := r.URL.Host
	if !HasPort.MatchString(host) {
		host += ":21"
	}

	reqSend := r
	if r.URL.Scheme == "ftp" || r.URL.Scheme == "ftps" {
		reqSend = new(http.Request)
		*reqSend = *r
		reqSend.URL = new(url.URL)
		*reqSend.URL = *r.URL
		reqSend.URL.Scheme = "http"
	}
	requestDump, err := httputil.DumpRequestOut(reqSend, true)
	if err != nil {
		logging.Printf("ERROR", "doFtpUpstream: SessionID:%d Could not create request dump: %v\n", ctx.SessionNo, err)
	} else {
		dst := ctx.AccessLog.ProxyIP
		src := ctx.AccessLog.SourceIP
		err = protocol.WriteWireshark(ctx, true, ctx.SessionNo, src, dst, requestDump)
		if err != nil {
			logging.Printf("ERROR", "doFtpUpstream: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
		}
	}

	name, infected := viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, requestDump)
	if infected {
		if ctx.AccessLog.VirusList == "" {
			ctx.AccessLog.VirusList = name
		} else {
			ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
		}
		logging.Printf("INFO", "doFtpUpstream: SessionID:%d Request has virus: %s\n", ctx.SessionNo, name)
	}
	var resp *http.Response
	if infected && readconfig.Config.Clamd.Block {
		resp = &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     "403 Virus found",
			Header:     make(http.Header),
			Body:       http.NoBody, // You can set a custom body if needed
		}
	} else {

		logging.Printf("DEBUG", "doFtpUpstream: SessionID:%d New Connection to %s\n", ctx.SessionNo, host)
		resp, err = ctx.Rt.RoundTrip(r)
		if err != nil {
			ctx.doError("Ftp", ErrRemoteConnect, err)
			if resp != nil {
				ctx.AccessLog.Status = resp.Status
			} else {
				ctx.AccessLog.Status = "404 " + err.Error()
			}
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.AccesslogWrite(ctx.AccessLog)
			ctx.AccessLog.Starttime = time.Now()
			ctx.AccessLog.BytesIN = 0
			ctx.AccessLog.BytesOUT = 0
			logging.Printf("DEBUG", "doFtpUpstream: SessionID:%d Connection closed.\n", ctx.SessionNo)
			return false, err
		}
	}
	bodySize := r.ContentLength

	headerSize := 0
	for name, values := range r.Header {
		for _, value := range values {
			headerSize += len(name) + len(value) + len(": ") + len("\r\n")
		}
	}
	// it seems host header information is moved to different entries in structure
	if r.Host == "" {
		headerSize += len("Host: ") + len(r.URL.Host) + len("\r\n")
		if !HasPort.MatchString(r.URL.Host) {
			headerSize += 3
		}
	} else {
		headerSize += len("Host: ") + len(r.Host) + len("\r\n")
		if !HasPort.MatchString(r.Host) {
			headerSize += 3
		}
	}
	// Adding the size of the initial request line and the final empty line
	requestLineSize := len(r.Method) + 1 + len(r.URL.String()) + len(" HTTP/1.1\r\n")
	finalEmptyLineSize := len("\r\n")
	// Calculate the total request size
	totalSize := requestLineSize + headerSize + int(bodySize) + finalEmptyLineSize
	ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + int64(totalSize)

	ctx.AccessLog.Status = resp.Status
	resp.Request = r
	resp.TransferEncoding = nil

	responseDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		logging.Printf("ERROR", "doFtpUpstream: SessionID:%d Could not create response dump: %v\n", ctx.SessionNo, err)
	} else {
		dst := ctx.AccessLog.ProxyIP
		src := ctx.AccessLog.SourceIP
		err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, dst, src, responseDump)
		if err != nil {
			logging.Printf("ERROR", "doFtpUpstream: SessionID:%d Could not write to Wireshark: %v\n", ctx.SessionNo, err)
		}
	}

	name, infected = viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, responseDump)
	if infected {
		if ctx.AccessLog.VirusList == "" {
			ctx.AccessLog.VirusList = name
		} else {
			ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
		}
		logging.Printf("INFO", "doFtpUpstream: SessionID:%d Response has virus: %s\n", ctx.SessionNo, name)
	}
	if infected && readconfig.Config.Clamd.Block {
		resp = &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     "403 Virus found",
			Header:     make(http.Header),
			Body:       http.NoBody, // You can set a custom body if needed
		}
	}

	err = ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Request", ErrResponseWrite, err)
		ctx.AccessLog.Status = "500 " + err.Error()
	} else {
		bodySize := resp.ContentLength
		// Calculate the size of the headers
		headerSize := 0
		for name, values := range resp.Header {
			for _, value := range values {
				// Via header added by this proxy to client
				if strings.ToUpper(name) != "VIA" {
					headerSize += len(name) + len(value) + len(": ") + len("\r\n")
				}
			}
		}
		headerEmptyLineSize := len("\r\n")
		responseLineSize := len(resp.Status) + len(" HTTP/1.1\r\n")
		// Calculate the total request size
		totalSize := responseLineSize + headerSize + headerEmptyLineSize + int(bodySize)
		ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(totalSize)
	}
	logging.Printf("DEBUG", "doFtpUpstream: SessionID:%d Connection closed.\n", ctx.SessionNo)
	ctx.AccessLog.Endtime = time.Now()
	ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
	logging.AccesslogWrite(ctx.AccessLog)
	ctx.AccessLog.Starttime = time.Now()
	ctx.AccessLog.BytesIN = 0
	ctx.AccessLog.BytesOUT = 0
	return true, err
}

func (ctx *Context) doFtp(w http.ResponseWriter, r *http.Request) (bool, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)

	var timeOut time.Duration = time.Duration(readconfig.Config.Connection.Timeout)
	//	var keepAlive time.Duration = time.Duration(readconfig.Config.Connection.Keepalive)

	var ftpClient *goftp.Client
	var err error
	var respCode int
	respHeader := http.Header{}

	if r.Body != nil {
		defer r.Body.Close()
	}

	if r.URL.Scheme != "ftp" && r.URL.Scheme != "ftps" {
		return false, nil
	}

	proxy := ctx.UpstreamProxy

	if proxy != "" {
		return ctx.doFtpUpstream(w, r)

	}

	parsedURL, _ := url.Parse(r.URL.String())
	port := parsedURL.Port()
	host := r.URL.Host
	method := r.Method
	user := readconfig.Config.FTP.Username
	pass := readconfig.Config.FTP.Password
	if r.URL.User != nil {
		user = r.URL.User.Username()
		upass, set := r.URL.User.Password()
		if set {
			pass = upass
		}
	}

	logging.Printf("DEBUG", "doFtp: SessionID:%d New Connection to %s\n", ctx.SessionNo, host)
	logging.Printf("DEBUG", "doFtp: SessionID:%d Set Username to %s\n", ctx.SessionNo, user)
	logging.Printf("DEBUG", "doFtp: SessionID:%d Method %s\n", ctx.SessionNo, method)

	reqSend := r
	if r.URL.Scheme == "ftp" || r.URL.Scheme == "ftps" {
		reqSend = new(http.Request)
		*reqSend = *r
		reqSend.URL = new(url.URL)
		*reqSend.URL = *r.URL
		reqSend.URL.Scheme = "http"
	}
	requestDump, err := httputil.DumpRequestOut(reqSend, true)
	if err != nil {
		logging.Printf("ERROR", "doFtp: SessionID:%d Could not create request dump: %v\n", ctx.SessionNo, err)
	} else {
		dst := ctx.AccessLog.ProxyIP
		src := ctx.AccessLog.SourceIP
		err = protocol.WriteWireshark(ctx, true, ctx.SessionNo, src, dst, requestDump)
		if err != nil {
			logging.Printf("ERROR", "doFtp: SessionID:%d Could not write to Wireshark: %v\n", ctx.SessionNo, err)
		}
	}

	name, infected := viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, requestDump)
	if infected {
		if ctx.AccessLog.VirusList == "" {
			ctx.AccessLog.VirusList = name
		} else {
			ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
		}
		logging.Printf("INFO", "doFtp: SessionID:%d Request has virus: %s\n", ctx.SessionNo, name)
	}

	buf := new(bytes.Buffer)
	if infected && readconfig.Config.Clamd.Block {
		respCode = http.StatusForbidden
		respHeader.Set("Content-Type", "application/octet-stream")
		respHeader.Set("Connection", "close")
		buf.WriteString("")
		ctx.AccessLog.Status = "403 Virus found"
	} else {
		// Try to count bytes send & received based on log data
		// It will miss
		// 	first 220 Header from server
		// 	Password length as it is hidden
		// Also directory data count is not exact as size is converted to bytes, kB, MB, etc.
		// Creates only one access log entry with bytesIN & bytesOUT from control and data connection combined.
		counterMap := make(map[int64]bytesCounter)
		ftpBytesCounter := counterMap[ctx.SessionNo]
		logWriter := &ftpLogWriter{bytes: &ftpBytesCounter, sessionNo: ctx.SessionNo}
		ftpClientConfig := goftp.Config{
			User:               user,
			Password:           pass,
			ConnectionsPerHost: 1,
			Timeout:            timeOut * time.Second,
			Logger:             logWriter,
		}
		if !HasPort.MatchString(host) {
			host += ":21"
			port = "21"
		}
		ftpClient, err = goftp.DialConfig(ftpClientConfig, host)
		ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + int64(len(pass)-6)
		if err != nil {
			b := true
			ctx.doError("Ftp", ErrRemoteConnect, err)
			ctx.AccessLog.Status = "500 " + err.Error()
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.Printf("DEBUG", "doFtp: SessionID:%d goftp.Error.Code(): %v\n", ctx.SessionNo, err)
			if ftpClient != nil {
				if err.(goftp.Error).Code() == 530 {
					b = false
					ctx.AccessLog.Status = "403 login failed"
				}
			}
			ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
			ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT
			logging.AccesslogWrite(ctx.AccessLog)
			ctx.AccessLog.Starttime = time.Now()
			ctx.AccessLog.BytesIN = 0
			ctx.AccessLog.BytesOUT = 0
			logging.Printf("DEBUG", "doFtp: SessionID:%d Connection closed.\n", ctx.SessionNo)
			return b, err
		}
		defer ftpClient.Close()

		// Use data conection creation to find remote IP
		rawConn, err := ftpClient.OpenRawConn()
		if err != nil {
			logging.Printf("ERROR", "doFtp: SessionID:%d Error opening raw connection: %v\n", ctx.SessionNo, err)
			ctx.AccessLog.Status = "500 " + err.Error()
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
			ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT
			logging.AccesslogWrite(ctx.AccessLog)
			ctx.AccessLog.Starttime = time.Now()
			ctx.AccessLog.BytesIN = 0
			ctx.AccessLog.BytesOUT = 0
			logging.Printf("DEBUG", "doFtp: SessionID:%d Connection closed.\n", ctx.SessionNo)
			return true, err
		}

		// Prepare the data connection
		dcGetter, err := rawConn.PrepareDataConn()
		if err != nil {
			logging.Printf("ERROR", "doFtp: SessionID:%d Error preparing data connection: %v\n", ctx.SessionNo, err)
			ctx.AccessLog.Status = "500 " + err.Error()
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
			ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT
			logging.AccesslogWrite(ctx.AccessLog)
			ctx.AccessLog.Starttime = time.Now()
			ctx.AccessLog.BytesIN = 0
			ctx.AccessLog.BytesOUT = 0
			logging.Printf("DEBUG", "doFtp: SessionID:%d Connection closed.\n", ctx.SessionNo)
			return true, err
		}
		dataConn, err := dcGetter()
		if err != nil {
			logging.Printf("ERROR", "doFtp: SessionID:%d Error getting data connection: %v\n", ctx.SessionNo, err)
			ctx.AccessLog.Status = "500 " + err.Error()
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
			ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT
			logging.AccesslogWrite(ctx.AccessLog)
			ctx.AccessLog.Starttime = time.Now()
			ctx.AccessLog.BytesIN = 0
			ctx.AccessLog.BytesOUT = 0
			logging.Printf("DEBUG", "doFtp: SessionID:%d Connection closed.\n", ctx.SessionNo)
			return true, err
		}
		dataConn.Close()
		remoteAddr := dataConn.RemoteAddr().(*net.TCPAddr)
		// Replace high port of data connection with control connection port
		ctx.AccessLog.DestinationIP = remoteAddr.IP.String() + ":" + port

		if strings.ToUpper(method) == "PUT" {
			logging.Printf("DEBUG", "doFtp: SessionID:%d Storing File: %s\n", ctx.SessionNo, r.URL.Path)
			ioBuf, err := io.ReadAll(r.Body)
			if err != nil {
				logging.Printf("ERROR", "doFtp: SessionID:%d could not receive File %v\n", ctx.SessionNo, err)
				logging.Printf("DEBUG", "doFtp: SessionID:%d Error writing file.\n", ctx.SessionNo)
				ctx.doError("Ftp", ErrRemoteConnect, err)
				ctx.AccessLog.Status = "500 " + err.Error()
				ctx.AccessLog.Endtime = time.Now()
				ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
				ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT
				logging.AccesslogWrite(ctx.AccessLog)
				ctx.AccessLog.Starttime = time.Now()
				ctx.AccessLog.BytesIN = 0
				ctx.AccessLog.BytesOUT = 0
				logging.Printf("DEBUG", "doFtp: SessionID:%d Connection closed.\n", ctx.SessionNo)
				return true, err
			}
			err = ftpClient.Store(r.URL.Path, bytes.NewBuffer(ioBuf))
			ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + int64(len(pass)-6)
			if err != nil {
				b := true
				logging.Printf("ERROR", "doFtp: SessionID:%d Error writing file.\n", ctx.SessionNo)
				ctx.doError("Ftp", ErrRemoteConnect, err)
				ctx.AccessLog.Status = "500 " + err.Error()
				if err.(goftp.Error).Code() == 530 {
					b = false
					ctx.AccessLog.Status = "403 login failed"
				}
				ctx.AccessLog.Endtime = time.Now()
				ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
				ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT
				logging.AccesslogWrite(ctx.AccessLog)
				ctx.AccessLog.Starttime = time.Now()
				ctx.AccessLog.BytesIN = 0
				ctx.AccessLog.BytesOUT = 0
				logging.Printf("DEBUG", "doFtp: SessionID:%d Connection closed.\n", ctx.SessionNo)
				return b, err
			} else {
				// logging.Printf("DEBUG", "doFtp: SessionID:%d Content: %s\n", ctx.SessionNo, buf)
				respHeader.Set("Content-Type", "application/octet-stream")
				respCode = 200
				ctx.AccessLog.Status = "200 OK"
				ctx.AccessLog.Endtime = time.Now()
				ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(len("226 Transfer complete.")+2)
				ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT + int64(len(ioBuf))
				logging.AccesslogWrite(ctx.AccessLog)
				ctx.AccessLog.Starttime = time.Now()
				ctx.AccessLog.BytesIN = 0
				ctx.AccessLog.BytesOUT = 0
			}
		} else {
			logging.Printf("DEBUG", "doFtp: SessionID:%d Retrieving File/Dir Listing: \n", ctx.SessionNo)
			err = ftpClient.Retrieve(r.URL.Path, buf)
			ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + int64(len(pass)-6)
			if err != nil {
				if err.(goftp.Error).Code() > 499 && err.(goftp.Error).Code() < 600 {
					files, err := ftpClient.ReadDir(r.URL.Path)
					if err != nil {
						b := true
						ctx.doError("Ftp", ErrRemoteConnect, err)
						ctx.AccessLog.Status = "500 " + err.Error()
						ctx.AccessLog.Endtime = time.Now()
						ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
						if err.(goftp.Error).Code() == 530 {
							b = false
							ctx.AccessLog.Status = "403 login failed"
						}
						ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
						ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT
						logging.AccesslogWrite(ctx.AccessLog)
						ctx.AccessLog.Starttime = time.Now()
						ctx.AccessLog.BytesIN = 0
						ctx.AccessLog.BytesOUT = 0
						logging.Printf("DEBUG", "doFtp: SessionID:%d Connection closed.\n", ctx.SessionNo)
						return b, err
					} else {
						hasSlash, _ := regexp.MatchString("^/", r.URL.Path)
						path := r.URL.Path
						if hasSlash {
							path = path[1:]
						}
						logging.Printf("DEBUG", "doFtp: SessionID:%d Directory Listing: \n", ctx.SessionNo)
						logging.Printf("DEBUG", "doFtp: SessionID:%d FTP Directory Listing: ftp://%s/%s\n", ctx.SessionNo, host, path)
						logging.Printf("DEBUG", "doFtp: SessionID:%d Parent Directory: ftp://%s/%s\n", ctx.SessionNo, host, filepath.Dir(path))
						// Write the response body
						fmt.Fprintf(buf, "Directory Listing: \n")
						fmt.Fprintf(buf, "FTP Directory Listing: ftp://%s/%s\n", host, path)
						fmt.Fprintf(buf, "Parent Directory: ftp://%s/%s\n", host, filepath.Dir(path))
						for _, file := range files {
							if file.IsDir() {
								logging.Printf("DEBUG", "doFtp: SessionID:%d %s dir %s\n", ctx.SessionNo, file.ModTime().Format(time.UnixDate), file.Name())
								n, _ := fmt.Fprintf(buf, "%s dir %s\n", file.ModTime().Format(time.UnixDate), file.Name())
								ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(n)
							} else {
								readableSize := formatSize(file.Size())
								logging.Printf("DEBUG", "doFtp: SessionID:%d %s %s %s\n", ctx.SessionNo, file.ModTime().Format(time.UnixDate), readableSize, file.Name())
								n, _ := fmt.Fprintf(buf, "%s %s %s\n", file.ModTime().Format(time.UnixDate), readableSize, file.Name())
								ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(n)
							}
						}
						respCode = 200
						respHeader.Set("Content-Type", "text/plain")
						ctx.AccessLog.Status = "200 OK"
						ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
						ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT
					}
				} else {
					ctx.doError("Ftp", ErrRemoteConnect, err)
					ctx.AccessLog.Status = "500 " + err.Error()
					ctx.AccessLog.Endtime = time.Now()
					ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
					ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
					ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT
					logging.AccesslogWrite(ctx.AccessLog)
					ctx.AccessLog.Starttime = time.Now()
					ctx.AccessLog.BytesIN = 0
					ctx.AccessLog.BytesOUT = 0
					logging.Printf("DEBUG", "doFtp: SessionID:%d Connection closed.\n", ctx.SessionNo)
					return true, err
				}
			} else {
				// logging.Printf("DEBUG", "doFtp: SessionID:%d Content: %s\n", ctx.SessionNo, buf)
				respHeader.Set("Content-Type", "application/octet-stream")
				respCode = 200
				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(buf.Len())
				ctx.AccessLog.Status = "200 OK"
				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + ftpBytesCounter.totalBytesIN
				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(len("226 Transfer complete.")+2)
				ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + ftpBytesCounter.totalBytesOUT
			}
		}
		respHeader.Set("Connection", "close")

		st := http.StatusText(respCode)
		if st != "" {
			st = " " + st
		}
		var bodyReadCloser io.ReadCloser
		var bodyContentLength = int64(0)
		body := buf.Bytes()
		if body != nil {
			bodyReadCloser = ioutil.NopCloser(bytes.NewBuffer(body))
			bodyContentLength = int64(len(body))
		}
		resp := &http.Response{
			Status:        fmt.Sprintf("%d%s", respCode, st),
			StatusCode:    respCode,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        respHeader,
			Body:          bodyReadCloser,
			ContentLength: bodyContentLength,
		}
		responseDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			logging.Printf("ERROR", "doFtp: SessionID:%d Could not create response dump: %v\n", ctx.SessionNo, err)
		} else {
			dst := ctx.AccessLog.DestinationIP
			src := ctx.AccessLog.SourceIP
			err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, dst, src, responseDump)
			if err != nil {
				logging.Printf("ERROR", "doFtp: SessionID:%d Could not write to Wireshark: %v\n", ctx.SessionNo, err)
			}
		}

		name, infected = viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, responseDump)
		if infected {
			if ctx.AccessLog.VirusList == "" {
				ctx.AccessLog.VirusList = name
			} else {
				ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
			}
			logging.Printf("INFO", "doFtp: SessionID:%d Response has virus: %s\n", ctx.SessionNo, name)
		}
		if infected && readconfig.Config.Clamd.Block {
			respCode = http.StatusForbidden
			respHeader.Set("Content-Type", "application/octet-stream")
			respHeader.Set("Connection", "close")
			buf.WriteString("")
			ctx.AccessLog.Status = "403 Virus found"
		}
	}

	err = ServeInMemory(w, respCode, respHeader, buf.Bytes())
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("doFtp", ErrResponseWrite, err)
	}
	logging.Printf("DEBUG", "doFtp: SessionID:%d Connection closed.\n", ctx.SessionNo)

	ctx.AccessLog.Endtime = time.Now()
	ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
	logging.AccesslogWrite(ctx.AccessLog)
	ctx.AccessLog.Starttime = time.Now()
	ctx.AccessLog.BytesIN = 0
	ctx.AccessLog.BytesOUT = 0

	return true, err
}

func (ctx *Context) doConnect(w http.ResponseWriter, r *http.Request) (b bool) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)

	b = true
	if r.Method != "CONNECT" {
		b = false
		return
	}

	hij, ok := w.(http.Hijacker)
	if !ok {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Connect", ErrNotSupportHijacking, nil)
		ctx.AccessLog.Status = "500 internal error ErrNotSupportHijacking"
		ctx.AccessLog.Endtime = time.Now()
		ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
		logging.AccesslogWrite(ctx.AccessLog)
		ctx.AccessLog.Starttime = time.Now()
		ctx.AccessLog.BytesIN = 0
		ctx.AccessLog.BytesOUT = 0
		logging.Printf("DEBUG", "doConnect: SessionID:%d Connection closed.\n", ctx.SessionNo)
		return
	}
	conn, _, err := hij.Hijack()
	if err != nil {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Connect", ErrNotSupportHijacking, err)
		ctx.AccessLog.Status = "500 internal error ErrNotSupportHijacking"
		ctx.AccessLog.Endtime = time.Now()
		ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
		logging.AccesslogWrite(ctx.AccessLog)
		ctx.AccessLog.Starttime = time.Now()
		ctx.AccessLog.BytesIN = 0
		ctx.AccessLog.BytesOUT = 0
		logging.Printf("DEBUG", "doConnect: SessionID:%d Connection closed.\n", ctx.SessionNo)
		return
	}
	hijConn := conn
	ctx.AccessLog.ProxyIP = hijConn.LocalAddr().String()
	ctx.AccessLog.SourceIP = hijConn.RemoteAddr().String()
	ctx.AccessLog.UpstreamProxyIP = ""
	ctx.ConnectReq = r
	ctx.ConnectAction = ConnectProxy
	host := r.URL.Host
	if !HasPort.MatchString(host) {
		host += ":80"
	}
	if ctx.Prx.OnConnect != nil {
		var newHost string
		ctx.ConnectAction, newHost = ctx.onConnect(host)
		if newHost != "" {
			host = newHost
		}
	}
	if !HasPort.MatchString(host) {
		host += ":80"
	}
	ctx.ConnectHost = host
	logging.Printf("DEBUG", "doConnect: SessionID:%d New Connection to %s\n", ctx.SessionNo, host)

	reqSend := r
	if r.URL.Scheme == "https" || r.URL.Scheme == "" {
		reqSend = new(http.Request)
		*reqSend = *r
		reqSend.URL = new(url.URL)
		*reqSend.URL = *r.URL
		reqSend.URL.Scheme = "http"
	}

	requestDump, err := httputil.DumpRequestOut(reqSend, true)
	if err != nil {
		logging.Printf("ERROR", "doConnect: SessionID:%d Could not create request dump: %v\n", ctx.SessionNo, err)
	} else {
		dst := ctx.AccessLog.ProxyIP
		src := ctx.AccessLog.SourceIP
		err = protocol.WriteWireshark(ctx, true, ctx.SessionNo, src, dst, requestDump)
		if err != nil {
			logging.Printf("ERROR", "doConnect: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
		}
	}
	switch ctx.ConnectAction {
	case ConnectProxy:
		conn, err := ctx.Dial(ctx, "tcp", host)
		if err != nil {
			hijConn.Write([]byte("HTTP/1.1 500 Can't connect to host\r\n\r\n"))
			hijConn.Close()
			ctx.doError("Connect", ErrRemoteConnect, err)
			ctx.AccessLog.Status = "500 " + err.Error()
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.AccesslogWrite(ctx.AccessLog)
			ctx.AccessLog.Starttime = time.Now()
			ctx.AccessLog.BytesIN = 0
			ctx.AccessLog.BytesOUT = 0
			src := ctx.AccessLog.ProxyIP
			dst := ctx.AccessLog.SourceIP
			err := protocol.WriteWireshark(ctx, false, ctx.SessionNo, src, dst, []byte("HTTP/1.1 500 Can't connect to host\r\n\r\n"))
			if err != nil {
				logging.Printf("ERROR", "doConnect: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
			}
			logging.Printf("DEBUG", "doConnect: SessionID:%d Connection closed.\n", ctx.SessionNo)
			return
		}
		remoteConn := conn.(*net.TCPConn)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Write([]byte("HTTP/1.1 500 Can't connect to host\r\n\r\n"))
			hijConn.Close()
			remoteConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrResponseWrite, err)
				ctx.AccessLog.Status = "500 " + err.Error()
				ctx.AccessLog.Endtime = time.Now()
				ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
				logging.AccesslogWrite(ctx.AccessLog)
				ctx.AccessLog.Starttime = time.Now()
				ctx.AccessLog.BytesIN = 0
				ctx.AccessLog.BytesOUT = 0
			}
			src := ctx.AccessLog.ProxyIP
			dst := ctx.AccessLog.SourceIP
			err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, src, dst, []byte("HTTP/1.1 500 Can't connect to host\r\n\r\n"))
			if err != nil {
				logging.Printf("ERROR", "doConnect: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
			}
			logging.Printf("DEBUG", "doConnect: SessionID:%d Connection closed.\n", ctx.SessionNo)
			return
		}
		src := ctx.AccessLog.ProxyIP
		dst := ctx.AccessLog.SourceIP
		err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, src, dst, []byte("HTTP/1.1 200 OK\r\n\r\n"))
		if err != nil {
			logging.Printf("ERROR", "doConnect: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
		}
		if ctx.AccessLog.Status == "" {
			// Proxy Dial sets status if a proxy is used
			ctx.AccessLog.Status = "200 OK"
		}
		var FirstPacket bool = true
		var FirstPacketResponse bool = true
		var wg sync.WaitGroup

		wg.Add(2)
		go func() {
			defer wg.Done()
			defer func() {
				e := recover()
				err, ok := e.(error)
				if !ok {
					return
				}
				hijConn.Close()
				remoteConn.Close()
				if !isConnectionClosed(err) {
					// ctx.doError("Connect", ErrRequestRead, err)
					if strings.Contains(strings.ToLower(err.Error()), "virus") {
						ctx.AccessLog.Status = "403 " + err.Error()
					} else {
						ctx.AccessLog.Status = "500 " + err.Error()
					}
				}
			}()
			//
			// Analyse first packet for protocol idenification and SNI compliance
			//
			buf := make([]byte, 65535)
			if FirstPacket {
				n, err := hijConn.Read(buf)
				if err != nil && err != io.EOF {
					panic(err)
				}
				if n != 0 {
					name, infected := viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, buf[:n])
					if infected {
						if ctx.AccessLog.VirusList == "" {
							ctx.AccessLog.VirusList = name
						} else {
							ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
						}
						logging.Printf("INFO", "doConnect: SessionID:%d Request has virus: %s\n", ctx.SessionNo, name)
					}
					if !infected || (infected && !readconfig.Config.Clamd.Block) {
						_, err = remoteConn.Write(buf[:n])
						if err != nil {
							panic(err)
						}
					}
					dst := ctx.AccessLog.ProxyIP
					src := ctx.AccessLog.SourceIP
					err = protocol.WriteWireshark(ctx, true, ctx.SessionNo, src, dst, buf[:n])
					if err != nil {
						logging.Printf("ERROR", "doConnect: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
					}

					protocol, description := protocol.AnalyseFirstPacket(ctx.SessionNo, buf[:n])
					if protocol != "Unknown" {
						if protocol != "TLS" {
							logging.Printf("INFO", "doConnect: SessionID:%d Found tunnelled protocol in request: %s %s\n", ctx.SessionNo, protocol, description)
							spos := strings.Index(ctx.AccessLog.Protocol, "Upgrade")
							if spos >= 0 {
								ctx.AccessLog.Protocol = protocol + "/" + ctx.AccessLog.Protocol
							} else {
								ctx.AccessLog.Protocol = protocol
							}
						} else {
							logging.Printf("INFO", "doConnect: SessionID:%d Found in request: %s %s\n", ctx.SessionNo, protocol, description)
							spos := strings.Index(description, ":")
							if strings.HasPrefix(ctx.AccessLog.Protocol, "TLS") {
								ctx.AccessLog.Protocol = ctx.AccessLog.Protocol + ":" + description[spos+2:]
							} else {
								ctx.AccessLog.Protocol = protocol + ":" + description[spos+2:]
							}
						}
					}
					if strings.Index(protocol, "Upgrade") >= 0 && strings.Index(description, "websocket") >= 0 {
						logging.Printf("INFO", "doConnect: SessionID:%d Client requested websocket upgrade: %s %s\n", ctx.SessionNo, protocol, description)
						ctx.WebsocketState.Websocket = true
					} else {
						ctx.WebsocketState.Websocket = false
					}
					if infected && readconfig.Config.Clamd.Block {
						ctx.AccessLog.Status = "403 Virus found"
						panic(errors.New("Virus found"))
					}
				}
				FirstPacket = false
				ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + int64(n)
			}
			if ctx.WebsocketState.Websocket {
				logging.Printf("DEBUG", "doConnect: SessionID:%d Wait for client connection disconnect or timeout server connections after %d seconds\n", ctx.SessionNo, ctx.ReadTimeout)
			}

			for {
				var err error
				var n int
				buf := make([]byte, 65535)
				mbuf := make([]byte, 65535)
				if ctx.WebsocketState.Websocket {
					n, err = protocol.WebsocketRead(true, hijConn, ctx.ReadTimeout, ctx.SessionNo, buf, mbuf)
				} else {
					if ctx.ReadTimeout > 0 {
						hijConn.SetReadDeadline(time.Now().Add(time.Duration(ctx.ReadTimeout) * time.Second))
					}
					n, err = hijConn.Read(mbuf)
				}
				if err != nil {
					if err == io.EOF {
						break
					}
					panic(err)
				}
				if n != 0 {
					name, infected := viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, buf[:n])
					if infected {
						if ctx.AccessLog.VirusList == "" {
							ctx.AccessLog.VirusList = name
						} else {
							ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
						}
						logging.Printf("INFO", "doConnect: SessionID:%d Request has virus: %s\n", ctx.SessionNo, name)
					}
					if !infected || (infected && !readconfig.Config.Clamd.Block) {
						_, err = remoteConn.Write(mbuf[:n])
						if err != nil {
							panic(err)
						}
					}
					dst := ctx.AccessLog.ProxyIP
					src := ctx.AccessLog.SourceIP
					if readconfig.Config.Wireshark.UnmaskedWebSocket {
						err = protocol.WriteWireshark(ctx, true, ctx.SessionNo, src, dst, buf[:n])
					} else {
						err = protocol.WriteWireshark(ctx, true, ctx.SessionNo, src, dst, mbuf[:n])
					}
					if err != nil {
						logging.Printf("ERROR", "doConnect: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
					}
					if infected && readconfig.Config.Clamd.Block {
						ctx.AccessLog.Status = "403 Virus found"
						panic(errors.New("Virus found"))
					}
				}
				ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + int64(n)
				//if !ctx.Websocket {
				//	break
				//}
			}
			remoteConn.CloseWrite()
			if c, ok := hijConn.(*net.TCPConn); ok {
				c.CloseRead()
			}
		}()
		go func() {
			defer wg.Done()
			defer func() {
				e := recover()
				err, ok := e.(error)
				if !ok {
					return
				}
				hijConn.Close()
				remoteConn.Close()
				logging.Printf("DEBUG", "doConnect: SessionID:%d Server connection closed\n", ctx.SessionNo)
				if !isConnectionClosed(err) {
					//ctx.doError("Connect", ErrResponseWrite, err)
					if strings.Contains(strings.ToLower(err.Error()), "virus") {
						ctx.AccessLog.Status = "403 " + err.Error()
					} else {
						ctx.AccessLog.Status = "500 " + err.Error()
					}
				}
			}()
			//
			// Analyse first response packet for protocol idenification and SNI compliance
			//
			buf := make([]byte, 65535)
			if FirstPacketResponse {
				n, err := remoteConn.Read(buf)
				if err != nil && err != io.EOF {
					panic(err)
				}
				if n != 0 {
					name, infected := viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, buf[:n])
					if infected {
						if ctx.AccessLog.VirusList == "" {
							ctx.AccessLog.VirusList = name
						} else {
							ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
						}
						logging.Printf("INFO", "doConnect: SessionID:%d Response has virus: %s\n", ctx.SessionNo, name)
					}
					if !infected || (infected && !readconfig.Config.Clamd.Block) {
						_, err = hijConn.Write(buf[:n])
						if err != nil {
							panic(err)
						}
					}
					src := ctx.AccessLog.ProxyIP
					dst := ctx.AccessLog.SourceIP
					err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, src, dst, buf[:n])
					if err != nil {
						logging.Printf("ERROR", "doConnect: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
					}
					protocol, description := protocol.AnalyseFirstPacketResponse(ctx.SessionNo, buf[:n])
					if protocol != "Unknown" {
						if protocol != "TLS" {
							logging.Printf("INFO", "doConnect: SessionID:%d Found tunnelled protocol in response: %s %s\n", ctx.SessionNo, protocol, description)
							spos := strings.Index(description, ":")
							if ctx.AccessLog.Protocol != "" {
								ctx.AccessLog.Protocol = ctx.AccessLog.Protocol + "/" + protocol + ":" + description[spos+2:]
							} else {
								ctx.AccessLog.Protocol = protocol + ":" + description[spos+2:]
							}
						} else {
							logging.Printf("INFO", "doConnect: SessionID:%d Found in request: %s %s\n", ctx.SessionNo, protocol, description)
							spos := strings.Index(description, ":")
							tlsInfo := description[spos+2:]
							spos = strings.Index(tlsInfo, ":")
							tlsVersion := tlsInfo[:spos]
							tlsCipher := tlsInfo[spos+1:]
							if tlsVersion == "" {
								tlsVersion = "TLS ?"
							}
							if tlsCipher == "" {
								tlsCipher = "Cipher ?"
							}
							if ctx.AccessLog.Protocol != "" {
								if strings.HasPrefix(ctx.AccessLog.Protocol, "TLS") {
									ctx.AccessLog.Protocol = strings.ReplaceAll(ctx.AccessLog.Protocol, "TLS", tlsVersion+":"+tlsCipher)
								} else {
									ctx.AccessLog.Protocol = ctx.AccessLog.Protocol + "/" + tlsVersion + ":" + tlsCipher
								}
							} else {
								ctx.AccessLog.Protocol = tlsVersion + ":" + tlsCipher
							}
						}
					}
					if strings.Index(protocol, "Upgrade") >= 0 && strings.Index(description, "websocket") >= 0 {
						logging.Printf("INFO", "doConnect: SessionID:%d Server accepted websocket upgrade: %s %s\n", ctx.SessionNo, protocol, description)
						ctx.WebsocketState.Websocket = true
					} else {
						ctx.WebsocketState.Websocket = false
					}
					if infected && readconfig.Config.Clamd.Block {
						ctx.AccessLog.Status = "403 Virus found"
						panic(errors.New("Virus found"))
					}
				}

				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(n)
			}
			if ctx.WebsocketState.Websocket {
				logging.Printf("DEBUG", "doConnect: SessionID:%d Wait for server connection disconnect or timeout server connections after %d seconds\n", ctx.SessionNo, ctx.ReadTimeout)
			}
			for {
				var err error
				var n int
				buf := make([]byte, 65535)
				mbuf := make([]byte, 65535)
				if ctx.WebsocketState.Websocket {
					n, err = protocol.WebsocketRead(false, remoteConn, ctx.ReadTimeout, ctx.SessionNo, buf, mbuf)
				} else {
					if ctx.ReadTimeout > 0 {
						remoteConn.SetReadDeadline(time.Now().Add(time.Duration(ctx.ReadTimeout) * time.Second))
					}
					n, err = remoteConn.Read(mbuf)
				}
				if err != nil {
					if err == io.EOF {
						break
					}
					panic(err)
				}
				if n != 0 {
					name, infected := viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, buf[:n])
					if infected {
						if ctx.AccessLog.VirusList == "" {
							ctx.AccessLog.VirusList = name
						} else {
							ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
						}
						logging.Printf("INFO", "doConnect: SessionID:%d Response has virus: %s\n", ctx.SessionNo, name)
					}
					if !infected || (infected && !readconfig.Config.Clamd.Block) {
						_, err = hijConn.Write(mbuf[:n])
						if err != nil {
							panic(err)
						}
					}
					src := ctx.AccessLog.ProxyIP
					dst := ctx.AccessLog.SourceIP
					if readconfig.Config.Wireshark.UnmaskedWebSocket {
						err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, src, dst, buf[:n])
					} else {
						err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, src, dst, mbuf[:n])
					}
					if err != nil {
						logging.Printf("ERROR", "doConnect: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
					}

					if infected && readconfig.Config.Clamd.Block {
						ctx.AccessLog.Status = "403 Virus found"
						panic(errors.New("Virus found"))
					}
				}
				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(n)
				//if !ctx.Websocket {
				//	break
				//}
			}
			remoteConn.CloseRead()
			if c, ok := hijConn.(*net.TCPConn); ok {
				c.CloseWrite()
			}
		}()
		wg.Wait()

		logging.Printf("INFO", "doConnect: SessionID:%d Websocket identified in traffic: %t\n", ctx.SessionNo, ctx.WebsocketState.Websocket)
		ctx.WebsocketState.Websocket = false
		hijConn.Close()
		remoteConn.Close()
		logging.Printf("DEBUG", "doConnect: SessionID:%d Connection closed.\n", ctx.SessionNo)
		ctx.AccessLog.Endtime = time.Now()
		ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
		logging.AccesslogWrite(ctx.AccessLog)
		ctx.AccessLog.Starttime = time.Now()
		ctx.AccessLog.BytesIN = 0
		ctx.AccessLog.BytesOUT = 0
	case ConnectMitm:
		tlsConfig := &tls.Config{}
		cert := ctx.Prx.signer.SignHost(host)
		if cert == nil {
			hijConn.Close()
			ctx.doError("Connect", ErrTLSSignHost, err)
			ctx.AccessLog.Status = "500 " + err.Error()
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.AccesslogWrite(ctx.AccessLog)
			ctx.AccessLog.Starttime = time.Now()
			ctx.AccessLog.BytesIN = 0
			ctx.AccessLog.BytesOUT = 0
			logging.Printf("DEBUG", "doConnect: SessionID:%d Connection closed.\n", ctx.SessionNo)
			return
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, *cert)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrResponseWrite, err)
				ctx.AccessLog.Status = "500 " + err.Error()
			}
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.AccesslogWrite(ctx.AccessLog)
			ctx.AccessLog.Starttime = time.Now()
			ctx.AccessLog.BytesIN = 0
			ctx.AccessLog.BytesOUT = 0
			logging.Printf("DEBUG", "doConnect: SessionID:%d Connection closed.\n", ctx.SessionNo)
			return
		}
		dst := ctx.AccessLog.ProxyIP
		src := ctx.AccessLog.SourceIP
		err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, dst, src, []byte("HTTP/1.1 200 OK\r\n\r\n"))
		if err != nil {
			logging.Printf("ERROR", "doConnect: SessionID:%d Could not write to Wireshark: %v\n", ctx.SessionNo, err)
		}
		ctx.hijTLSConn = tls.Server(hijConn, tlsConfig)
		if err := ctx.hijTLSConn.Handshake(); err != nil {
			ctx.hijTLSConn.Close()
			if !isConnectionClosed(err) {
				ctx.doError("Connect", ErrTLSHandshake, err)
				ctx.AccessLog.Status = "500 " + err.Error()
			}
			ctx.AccessLog.Endtime = time.Now()
			ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
			logging.AccesslogWrite(ctx.AccessLog)
			ctx.AccessLog.Starttime = time.Now()
			ctx.AccessLog.BytesIN = 0
			ctx.AccessLog.BytesOUT = 0
			logging.Printf("DEBUG", "doConnect: SessionID:%d Connection closed.\n", ctx.SessionNo)
			return
		}
		if ctx.ReadTimeout > 0 {
			ctx.hijTLSConn.SetReadDeadline(time.Now().Add(time.Duration(ctx.ReadTimeout) * time.Second))
		}
		ctx.hijTLSReader = bufio.NewReader(ctx.hijTLSConn)
		b = false
	default:
		hijConn.Close()
		logging.Printf("DEBUG", "doConnect: SessionID:%d Connection closed.\n", ctx.SessionNo)
		ctx.AccessLog.Endtime = time.Now()
		ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
		logging.AccesslogWrite(ctx.AccessLog)
		ctx.AccessLog.Starttime = time.Now()
		ctx.AccessLog.BytesIN = 0
		ctx.AccessLog.BytesOUT = 0
	}
	return
}

func (ctx *Context) doMitm() (w http.ResponseWriter, r *http.Request) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	const maxPayloadLength int = 16 * 65535

	if ctx.WebsocketState.Websocket {
		// Not anymore HTTP Request / Response
		hijConn := ctx.hijTLSConn
		remoteConn := ctx.WebsocketState.WebsocketConn
		var hijRead bool = true
		var hijWrite bool = true
		var remoteRead bool = true
		var remoteWrite bool = true

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			defer func() {
				e := recover()
				err, ok := e.(error)
				if !ok {
					return
				}
				hijConn.Close()
				remoteConn.Close()
				logging.Printf("DEBUG", "doMitm: SessionID:%d Client connection closed\n", ctx.SessionNo)
				if !isConnectionClosed(err) {
					// ctx.doError("Connect", ErrRequestRead, err)
					if strings.Contains(strings.ToLower(err.Error()), "virus") {
						ctx.AccessLog.Status = "403 " + err.Error()
					} else {
						ctx.AccessLog.Status = "500 " + err.Error()
					}
				}
			}()
			//
			// Websocket Request
			//

			for {
				buf := make([]byte, 65535)
				mbuf := make([]byte, 65535)
				n, err := protocol.WebsocketRead(true, hijConn, ctx.ReadTimeout, ctx.SessionNo, buf, mbuf)
				if err != nil {
					if err == io.EOF {
						break
					}
					panic(err)
				}

				name, infected := viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, buf[:n])
				if infected {
					if ctx.AccessLog.VirusList == "" {
						ctx.AccessLog.VirusList = name
					} else {
						ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
					}
					logging.Printf("INFO", "doMitm: SessionID:%d Request has virus: %s\n", ctx.SessionNo, name)
					if readconfig.Config.Clamd.Block {
						ctx.AccessLog.Status = "403 Virus found"
						panic(errors.New("Virus found"))
					}
				}

				if n != 0 {
					remoteConn.SetDeadline(time.Now().Add(time.Duration(ctx.ReadTimeout) * time.Second))
					_, err := remoteConn.Write(mbuf[:n])
					if err != nil {
						panic(err)
					}

					dst := ctx.AccessLog.ProxyIP
					src := ctx.AccessLog.SourceIP
					if readconfig.Config.Wireshark.UnmaskedWebSocket {
						err = protocol.WriteWireshark(ctx, true, ctx.SessionNo, src, dst, buf[:n])
					} else {
						err = protocol.WriteWireshark(ctx, true, ctx.SessionNo, src, dst, mbuf[:n])
					}
					if err != nil {
						logging.Printf("ERROR", "doMitm: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
					}
				}
				ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + int64(n)
				//if !ctx.Websocket {
				//	break
				//}
			}
			remoteWrite = false
			if !remoteRead {
				logging.Printf("DEBUG", "doMitm: SessionID:%d remote close write\n", ctx.SessionNo)
				remoteConn.Close()
			}
			hijRead = false
			if !hijWrite {
				logging.Printf("DEBUG", "doMitm: SessionID:%d hij close read\n", ctx.SessionNo)
				hijConn.Close()
			}
		}()

		go func() {
			defer wg.Done()
			defer func() {
				e := recover()
				err, ok := e.(error)
				if !ok {
					return
				}
				hijConn.Close()
				remoteConn.Close()
				logging.Printf("DEBUG", "doMitm: SessionID:%d Server connection closed\n", ctx.SessionNo)
				if !isConnectionClosed(err) {
					// ctx.doError("Connect", ErrResponseWrite, err)
					if strings.Contains(strings.ToLower(err.Error()), "virus") {
						ctx.AccessLog.Status = "403 " + err.Error()
					} else {
						ctx.AccessLog.Status = "500 " + err.Error()
					}
				}
			}()
			//
			// Websocket Response
			//

			for {
				buf := make([]byte, 65535)
				mbuf := make([]byte, 65535)
				n, err := protocol.WebsocketRead(false, remoteConn, ctx.ReadTimeout, ctx.SessionNo, buf, mbuf)
				if err != nil {
					if err == io.EOF {
						break
					}
					panic(err)
				}

				name, infected := viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, buf[:n])
				if infected {
					if ctx.AccessLog.VirusList == "" {
						ctx.AccessLog.VirusList = name
					} else {
						ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
					}
					logging.Printf("INFO", "doMitm: SessionID:%d Response has virus: %s\n", ctx.SessionNo, name)
					if readconfig.Config.Clamd.Block {
						ctx.AccessLog.Status = "403 Virus found"
						panic(errors.New("Virus found"))
					}
				}

				if n != 0 {
					hijConn.SetDeadline(time.Now().Add(time.Duration(ctx.ReadTimeout) * time.Second))
					_, err = hijConn.Write(mbuf[:n])
					if err != nil {
						panic(err)
					}

					src := ctx.AccessLog.ProxyIP
					dst := ctx.AccessLog.SourceIP
					if readconfig.Config.Wireshark.UnmaskedWebSocket {
						err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, src, dst, buf[:n])
					} else {
						err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, src, dst, mbuf[:n])
					}
					if err != nil {
						logging.Printf("ERROR", "doMitm: SessionID:%d Could not write to Wireshark %v\n", ctx.SessionNo, err)
					}
				}
				ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(n)
				//if !ctx.Websocket {
				//	break
				//}
			}
			remoteRead = false
			if !remoteWrite {
				logging.Printf("DEBUG", "doMitm: SessionID:%d remote close read\n", ctx.SessionNo)
				remoteConn.Close()
			}
			hijWrite = false
			if !hijRead {
				logging.Printf("DEBUG", "doMitm: SessionID:%d hij close write\n", ctx.SessionNo)
				hijConn.Close()
			}
		}()

		wg.Wait()
		logging.Printf("INFO", "doMitm: SessionID:%d Websocket: %t\n", ctx.SessionNo, ctx.WebsocketState.Websocket)
		hijConn.Close()
		remoteConn.Close()
		logging.Printf("DEBUG", "doMitm: SessionID:%d Connection closed.\n", ctx.SessionNo)
		ctx.AccessLog.Endtime = time.Now()
		ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
		ctx.AccessLog.Protocol = "Upgrade:websocket"
		logging.AccesslogWrite(ctx.AccessLog)
		ctx.AccessLog.Starttime = time.Now()
		ctx.AccessLog.BytesIN = 0
		ctx.AccessLog.BytesOUT = 0

	} else {
		logging.Printf("DEBUG", "doMitm: SessionID:%d Read Request\n", ctx.SessionNo)
		req, err := http.ReadRequest(ctx.hijTLSReader)
		if err != nil {
			if !isConnectionClosed(err) {
				ctx.doError("Request", ErrRequestRead, err)
			}
			return
		}
		req.RemoteAddr = ctx.ConnectReq.RemoteAddr
		if req.URL.IsAbs() {
			ctx.doError("Request", ErrAbsURLAfterCONNECT, nil)
			return
		}
		logging.Printf("INFO", "doMitm: SessionID:%d Requested URL: %s\n", ctx.SessionNo, req.URL.Redacted())
		req.URL.Scheme = "https"
		req.URL.Host = ctx.ConnectHost
		w = NewConnResponseWriter(ctx.hijTLSConn)
		r = req
		ctx.AccessLog.Method = r.Method
		ctx.AccessLog.Scheme = r.URL.Scheme
		ctx.AccessLog.Url = r.URL.Redacted()
		ctx.AccessLog.Version = r.Proto
	}
	return
}

func (ctx *Context) doRequest(w http.ResponseWriter, r *http.Request) (bool, error) {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	var err error
	if !r.URL.IsAbs() {
		if r.Body != nil {
			defer r.Body.Close()
		}
		err := ServeInMemory(w, 500, nil, []byte("This is a proxy server. Does not respond to non-proxy requests."))
		if err != nil && !isConnectionClosed(err) {
			ctx.doError("Request", ErrResponseWrite, err)
		}
		return true, err
	}

	if r.URL.Scheme == "ftp" {
		b, err := ctx.doFtp(w, r)
		if err != nil {
			respCode := 500
			respHeader := http.Header{}
			var bodyReadCloser io.ReadCloser
			var bodyContentLength = int64(0)
			if !b {
				respCode = 403
			}
			respHeader.Set("Content-Type", "application/octet-stream")
			respHeader.Set("Connection", "close")

			st := http.StatusText(respCode)
			if st != "" {
				st = " " + st + " " + err.Error()
			}
			st = st + " " + err.Error()
			resp := &http.Response{
				Status:        fmt.Sprintf("%d%s", respCode, st),
				StatusCode:    respCode,
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        respHeader,
				Body:          bodyReadCloser,
				ContentLength: bodyContentLength,
			}
			resp.Request = r
			resp.TransferEncoding = nil
			err = ServeResponse(w, resp)
			if err != nil && !isConnectionClosed(err) {
				ctx.doError("Request", ErrResponseWrite, err)
			}
		}
		return true, err
		// return ctx.doFtp(w, r)
	}

	r.RequestURI = r.URL.String()
	logging.Printf("DEBUG", "doRequest: SessionID:%d New Connection to %s\n", ctx.SessionNo, r.URL.Host)

	upgrade := r.Header.Get("Upgrade")
	if upgrade == "websocket" {
		logging.Printf("INFO", "doRequest: SessionID:%d Client requested websocket upgrade: Upgrade websocket\n", ctx.SessionNo)
	}

	requestDump, err := httputil.DumpRequestOut(r, true)
	if err != nil {
		logging.Printf("ERROR", "doRequest: SessionID:%d Could not create request dump: %v\n", ctx.SessionNo, err)
		return true, err
	}
	dst := ctx.AccessLog.ProxyIP
	src := ctx.AccessLog.SourceIP
	err = protocol.WriteWireshark(ctx, true, ctx.SessionNo, src, dst, requestDump)
	if err != nil {
		logging.Printf("ERROR", "doRequest: SessionID:%d Could not write to Wireshark: %v\n", ctx.SessionNo, err)
	}

	name, infected := viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, requestDump)
	if infected {
		if ctx.AccessLog.VirusList == "" {
			ctx.AccessLog.VirusList = name
		} else {
			ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
		}
		logging.Printf("INFO", "doRequest: SessionID:%d Request has virus: %s\n", ctx.SessionNo, name)
	}
	var resp *http.Response
	if infected && readconfig.Config.Clamd.Block {
		resp = &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     "403 Virus found",
			Header:     make(http.Header),
			Body:       http.NoBody, // You can set a custom body if needed
		}
	} else {

		if ctx.Prx.OnRequest == nil {
			return false, nil
		}
		resp = ctx.onRequest(r)
		if resp == nil {
			return false, nil
		}
		if r.Body != nil {
			defer r.Body.Close()
		}
	}
	resp.Request = r
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	err = ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Request", ErrResponseWrite, err)
	}
	logging.Printf("DEBUG", "doRequest: SessionID:%d Connection closed.\n", ctx.SessionNo)
	ctx.AccessLog.Endtime = time.Now()
	ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
	logging.AccesslogWrite(ctx.AccessLog)
	ctx.AccessLog.Starttime = time.Now()
	ctx.AccessLog.BytesIN = 0
	ctx.AccessLog.BytesOUT = 0
	return true, err
}

func (ctx *Context) doResponse(w http.ResponseWriter, r *http.Request) error {
	logging.Printf("TRACE", "%s: SessionID:%d called\n", logging.GetFunctionName(), ctx.SessionNo)
	if r.Body != nil {
		defer r.Body.Close()
	}
	var bodySize int64
	var err error
	var resp *http.Response

	upgrade := r.Header.Get("Upgrade")
	if upgrade == "websocket" {
		// Need to capture Upgrades as Rountripper can not deal with the 101 Upgrade response
		// The response does not have a body and Roundtripper waits for a body until it times out
		var host string
		if r.Host == "" {
			host = r.URL.Host
		} else {
			host = r.Host
		}
		logging.Printf("DEBUG", "doResponse: SessionID:%d connection upgrade: %s\n", ctx.SessionNo, upgrade)
		if !HasPort.MatchString(host) {
			switch r.URL.Scheme {
			case "http":
				host += ":80"
			case "https":
				host += ":443"
			default:
				host += ":443"
			}
		}
		ctx.WebsocketState.WebsocketConn, err = ctx.Dial(ctx, "tcp", host)
		if r.URL.Scheme == "https" {
			// TLS handshake to origin
			serverName := r.URL.Hostname()
			logging.Printf("DEBUG", "doResponse: SessionID:%d Setup TLS connection to %s\n", ctx.SessionNo, serverName)
			tlsConf := ctx.TLSConfig
			if tlsConf == nil {
				tlsConf = &tls.Config{}
			}
			if tlsConf.ServerName == "" {
				clone := tlsConf.Clone()
				clone.ServerName = serverName
				tlsConf = clone
			}
			tlsConn := tls.Client(ctx.WebsocketState.WebsocketConn, tlsConf)
			if err = tlsConn.Handshake(); err != nil {
				logging.Printf("ERROR", "doResponse: SessionID:%d TLS handshake to host %s failed: %v\n", ctx.SessionNo, serverName, err)
			} else {
				// After this point, tlsConn is the underlying socket. Avoid closing conn twice.
				ctx.WebsocketState.WebsocketConn = tlsConn
				state := tlsConn.ConnectionState()
				ctx.AccessLog.Protocol = tls.VersionName(state.Version) + ":" + tls.CipherSuiteName(state.CipherSuite) + ":" + tlsConf.ServerName
			}

		}

		if err != nil {
			logging.Printf("ERROR", "doResponse: SessionID:%d Connection to host %s failed: %v\n", ctx.SessionNo, host, err)
			return err
		} else {
			logging.Printf("DEBUG", "doResponse: SessionID:%d Connection to host %s succeded\n", ctx.SessionNo, host)
			err1 := r.Write(ctx.WebsocketState.WebsocketConn)
			if err1 != nil {
				logging.Printf("ERROR", "doResponse: SessionID:%d Could not send request to host: %v\n", ctx.SessionNo, host, err)
			}
			reader := bufio.NewReader(ctx.WebsocketState.WebsocketConn)
			resp, err = http.ReadResponse(reader, r)
			if err != nil {
				logging.Printf("ERROR", "doResponse: SessionID:%d Could not read response from  host: %v\n", ctx.SessionNo, err)
				return err
			}
		}
		logging.Printf("INFO", "doResponse: SessionID:%d Server accepted websocket upgrade: Upgrade to websocket\n", ctx.SessionNo)
		ctx.WebsocketState.Websocket = true
		ctx.Prx.MitmChunked = false
		bodySize = 0
	} else {
		logging.Printf("DEBUG", "doResponse: SessionID:%d Call RoundTrip\n", ctx.SessionNo)
		resp, err = ctx.Rt.RoundTrip(r)
		if err != nil {
			if strings.Contains(err.Error(), "HTTP_1_1_REQUIRED") || strings.Contains(err.Error(), "http2") {
				logging.Printf("INFO", "doResponse: SessionID:%d Retrying with HTTP/1.1\n", ctx.SessionNo)
				transportRt := ctx.Rt.(*http.Transport)
				transportRt.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
				resp, err = transportRt.RoundTrip(r)
			}
		}
		bodySize = r.ContentLength
	}
	headerSize := int64(0)
	for name, values := range r.Header {
		for _, value := range values {
			headerSize += int64(len(name) + len(value) + len(": ") + len("\r\n"))
		}
	}
	// it seems host header information is moved to different entries in structure
	if r.Host == "" {
		headerSize += int64(len("Host: ") + len(r.URL.Host) + len("\r\n"))
	} else {
		headerSize += int64(len("Host: ") + len(r.Host) + len("\r\n"))
	}
	// Added by roundtripper in transport request as extra header to server.
	headerSize += int64(len("Accept-Encoding: gzip\r\n"))
	// Adding the size of the initial request line and the final empty line
	requestLineSize := int64(len(r.Method) + 1 + len(r.URL.String()) + len(" HTTP/1.1\r\n"))
	finalEmptyLineSize := int64(len("\r\n"))
	// Calculate the total request size
	totalSize := requestLineSize + headerSize + bodySize + finalEmptyLineSize
	ctx.AccessLog.BytesOUT = ctx.AccessLog.BytesOUT + totalSize
	if err != nil {
		if err != context.Canceled && !isConnectionClosed(err) {
			ctx.doError("Response", ErrRoundTrip, err)
		}
		ctx.AccessLog.Status = "404 " + err.Error()
		err := ServeInMemory(w, 404, nil, nil)
		if err != nil && !isConnectionClosed(err) {
			ctx.doError("Response", ErrResponseWrite, err)
		}
		logging.Printf("DEBUG", "doResponse: SessionID:%d Connection closed.\n", ctx.SessionNo)
		ctx.AccessLog.Endtime = time.Now()
		ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
		logging.AccesslogWrite(ctx.AccessLog)
		ctx.AccessLog.Starttime = time.Now()
		ctx.AccessLog.BytesIN = 0
		ctx.AccessLog.BytesOUT = 0
		return err
	}

	responseDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		logging.Printf("ERROR", "doResponse: SessionID:%d Could not create response dump: %v\n", ctx.SessionNo, err)
		return err
	}
	dst := ctx.AccessLog.ProxyIP
	src := ctx.AccessLog.SourceIP
	err = protocol.WriteWireshark(ctx, false, ctx.SessionNo, dst, src, responseDump)
	if err != nil {
		logging.Printf("ERROR", "doResponse: SessionID:%d Could not write to Wireshark: %v\n", ctx.SessionNo, err)
	}

	name, infected := viruscheck.HasVirus(ctx.SessionNo, ctx.Prx.ClamdStruct, responseDump)
	if infected {
		if ctx.AccessLog.VirusList == "" {
			ctx.AccessLog.VirusList = name
		} else {
			ctx.AccessLog.VirusList = ctx.AccessLog.VirusList + ":" + name
		}
		logging.Printf("INFO", "doResponse: SessionID:%d Response has virus: %s\n", ctx.SessionNo, name)
	}
	if infected && readconfig.Config.Clamd.Block {
		resp = &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     "403 Virus found",
			Header:     make(http.Header),
			Body:       http.NoBody, // You can set a custom body if needed
		}
	} else {
		if ctx.Prx.OnResponse != nil {
			ctx.onResponse(r, resp)
		}
		resp.Request = r
		resp.TransferEncoding = nil
		if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
			resp.TransferEncoding = []string{"chunked"}
		}
	}
	err = ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Response", ErrResponseWrite, err)
		ctx.AccessLog.Status = "500 " + err.Error()
	} else {
		ctx.AccessLog.Status = resp.Status
		bodySize := resp.ContentLength
		// Calculate the size of the headers
		headerSize := 0
		for name, values := range resp.Header {
			for _, value := range values {
				// Via header added by this proxy to client
				if strings.ToUpper(name) != "VIA" {
					headerSize += len(name) + len(value) + len(": ") + len("\r\n")
				}
			}
		}
		headerEmptyLineSize := len("\r\n")
		responseLineSize := len(resp.Status) + len(" HTTP/1.1\r\n")
		// Calculate the total request size
		totalSize := responseLineSize + headerSize + headerEmptyLineSize + int(bodySize)
		ctx.AccessLog.BytesIN = ctx.AccessLog.BytesIN + int64(totalSize)
	}
	logging.Printf("DEBUG", "doResponse: SessionID:%d Connection closed.\n", ctx.SessionNo)
	ctx.AccessLog.Endtime = time.Now()
	ctx.AccessLog.Duration = ctx.AccessLog.Endtime.Sub(ctx.AccessLog.Starttime)
	logging.AccesslogWrite(ctx.AccessLog)
	ctx.AccessLog.Starttime = time.Now()
	ctx.AccessLog.BytesIN = 0
	ctx.AccessLog.BytesOUT = 0
	return err
}
