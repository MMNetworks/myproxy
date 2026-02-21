package dnshttp

import (
	"net"
	"net/http"
	"strconv"

	"codeberg.org/miekg/dns"
)

// ResponseWriter is DOH capable [dns.ResponseWriter].
type ResponseWriter struct {
	// Req is the original HTTP request.
	Req *http.Request
	// w is the http responseWriter we are wrapping.
	w http.ResponseWriter
	// laddr is the local address, it's partially tracked in the net/http package.
	laddr net.Addr
}

// NewResponseWriter returns a new ResponseWriter that embeds w. See [Request] for example usage in a http
// handler.
func NewResponseWriter(w http.ResponseWriter, req *http.Request, laddr net.Addr) *ResponseWriter {
	return &ResponseWriter{w: w, laddr: laddr, Req: req}
}

func (w *ResponseWriter) Conn() net.Conn        { return nil }
func (w *ResponseWriter) Session() *dns.Session { return nil }
func (w *ResponseWriter) Hijack()               {}
func (w *ResponseWriter) Close() error          { return nil }

// Write writes the [dns.Msg]'s byffer to the underlaying HTTP response writer. It sets a defaults
// cache-control of 600 seconds.
func (w *ResponseWriter) Write(p []byte) (n int, err error) {
	// this is a TCP response, the first 2 bytes, are the length, skip those.
	p = p[2:]
	w.w.Header().Set("Content-Type", MimeType)
	w.w.Header().Set("Cache-Control", "max-age=600")
	w.w.Header().Set("Content-Length", strconv.Itoa(len(p)))
	w.w.WriteHeader(http.StatusOK)
	return w.w.Write(p)
}

// LocalAddr implements the ResponseWriter.LocalAddr method.
func (w *ResponseWriter) LocalAddr() net.Addr { return w.laddr }

// RemoteAddr implements the ResponseWriter.RemoteAddr method.
func (w *ResponseWriter) RemoteAddr() net.Addr {
	h, p, _ := net.SplitHostPort(w.Req.RemoteAddr)
	return &net.TCPAddr{IP: net.ParseIP(h), Port: func(p string) int { i, _ := strconv.Atoi(p); return i }(p)}
}
