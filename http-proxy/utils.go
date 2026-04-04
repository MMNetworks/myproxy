package httpproxy

import (
	"bytes"
	"fmt"
	"io"
	"myproxy/logging"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// InMemoryResponse creates new HTTP response given arguments.
func InMemoryResponse(code int, header http.Header, body []byte) *http.Response {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	if header == nil {
		header = make(http.Header)
	}
	st := http.StatusText(code)
	if st != "" {
		st = " " + st
	}
	var bodyReadCloser io.ReadCloser
	var bodyContentLength = int64(0)
	if body != nil {
		bodyReadCloser = io.NopCloser(bytes.NewBuffer(body))
		bodyContentLength = int64(len(body))
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d%s", code, st),
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          bodyReadCloser,
		ContentLength: bodyContentLength,
	}
}

// ServeResponse serves HTTP response to http.ResponseWriter.
func ServeResponse(ctx *Context, w http.ResponseWriter, resp *http.Response) error {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	if resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	h := w.Header()
	for k, v := range resp.Header {
		tK := CleanUntrustedString(ctx, "Header key", k)
		for _, value := range v {
			tV := CleanUntrustedString(ctx, "Header Value", value)
			h.Add(tK, tV)
		}
	}
	if h.Get("Date") == "" {
		h.Set("Date", time.Now().UTC().Format("Mon, 2 Jan 2006 15:04:05")+" GMT")
	}
	if h.Get("Content-Type") == "" && resp.ContentLength != 0 {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	}
	if resp.ContentLength >= 0 {
		h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	} else {
		h.Del("Content-Length")
	}
	h.Del("Transfer-Encoding")
	te := ""
	if len(resp.TransferEncoding) > 0 {
		if len(resp.TransferEncoding) > 1 {
			return ErrUnsupportedTransferEncoding
		}
		te = CleanUntrustedString(ctx, "Transfer Encoding", resp.TransferEncoding[0])
	}
	h.Del("Connection")
	clientConnection := ""
	if resp.Request != nil {
		clientConnection = strings.ToLower(CleanUntrustedString(ctx, "Connection", resp.Request.Header.Get("Connection")))
	}
	switch clientConnection {
	case "close":
		h.Set("Connection", "close")
	case "keep-alive":
		if h.Get("Content-Length") != "" || te == "chunked" {
			h.Set("Connection", "keep-alive")
		} else {
			h.Set("Connection", "close")
		}
	case "upgrade":
		h.Set("Connection", "Upgrade")
	default:
		if te == "chunked" {
			h.Set("Connection", "close")
		}
	}
	switch te {
	case "":
		w.WriteHeader(resp.StatusCode)
		if resp.Body != nil {
			if _, err := io.Copy(w, resp.Body); err != nil {
				return err
			}
		}
	case "chunked":
		if h.Get("Content-Length") != "" {
			h.Del("Content-Length")
			logging.Printf("DEBUG", "don't allow content-length with chunked encoding")
		}
		// #nosec G113 -- content-length is removed before response is send
		h.Set("Transfer-Encoding", "chunked")
		w.WriteHeader(resp.StatusCode)
		w2 := httputil.NewChunkedWriter(w)
		if resp.Body != nil {
			if _, err := io.Copy(w2, resp.Body); err != nil {
				return err
			}
		}
		if err := w2.Close(); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\r\n")); err != nil {
			return err
		}
	default:
		return ErrUnsupportedTransferEncoding
	}
	return nil
}

// ServeInMemory serves HTTP response given arguments to http.ResponseWriter.
func ServeInMemory(ctx *Context, w http.ResponseWriter, code int, header http.Header, body []byte) error {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	return ServeResponse(ctx, w, InMemoryResponse(code, header, body))
}

// HasPort returns if address has digits
var HasPort = regexp.MustCompile(`:\d+$`)

func stripPort(s string) string {
	logging.Printf("TRACE", "%s: called\n", logging.GetFunctionName())
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}
