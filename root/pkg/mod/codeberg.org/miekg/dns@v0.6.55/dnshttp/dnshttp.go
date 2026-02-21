// Package dnshttp deals with converting HTTP requests and responses to dns.Msg types. This is part of DNS
// over HTTP (DOH).
// The mandatory tls.Config must contain tlsConfig.NextProtos = []string{"h2", "http/1.1"}, see [NextProtos].
package dnshttp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"codeberg.org/miekg/dns"
)

// MimeType is the DOH mimetype.
const MimeType = "application/dns-message"

// Path is the URL path that is used by DOH.
const Path = "/dns-query"

// NextProtos is the configuration a tls.Config must carry to be compatible with most clients.
var NextProtos = []string{"h2", "http/1.1"}

// NewRequest returns a new DOH request given a HTTP method, URL and a [dns.Msg].
//
// The URL should not have a path, so "/dns-query" should be excluded. The URL must have a scheme, although
// this isn't checked. Supported methods are GET or POST. NewRequest call Pack on m and sets m.ID to zero.
func NewRequest(method, URL string, m *dns.Msg) (*http.Request, error) {
	m.ID = 0
	if err := m.Pack(); err != nil {
		return nil, err
	}

	URL, err := url.JoinPath(URL, Path)
	if err != nil {
		return nil, err
	}

	switch method {
	case http.MethodGet:
		b64 := base64.RawURLEncoding.EncodeToString(m.Data)
		req, err := http.NewRequest(method, URL+"?dns="+b64, nil)
		if err != nil {
			return req, err
		}
		req.Header.Set("Content-Type", MimeType)
		req.Header.Set("Accept", MimeType)
		return req, nil
	case http.MethodPost:
		req, err := http.NewRequest(method, URL, bytes.NewReader(m.Data))
		if err != nil {
			return req, err
		}
		req.Header.Set("Content-Type", MimeType)
		req.Header.Set("Accept", MimeType)
		return req, nil
	}
	return nil, fmt.Errorf("%s: %s", http.StatusText(http.StatusMethodNotAllowed), method)
}

// Request converts req to a [dns.Msg]. This is used inside the ServerHTTP method to make a [dns.Msg] that will
// then be given to the (embedded) [dns.ServeMux]:
//
//	func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
//		m, err := dnshttp.Request(r)
//		if err != nil {
//			http.Error(w, err.Error(), http.StatusBadRequest)
//			return
//		}
//		hw := dnshttp.NewResponseWriter(w, r, r.Context().Value(http.LocalAddrContextKey).(net.Addr))
//		h.mux.ServeDNS(context.Background(), hw, m) // assuming *handler embeds a dns.ServeMux
//	}
func Request(req *http.Request) (*dns.Msg, error) {
	switch req.Method {
	case http.MethodGet:
		values := req.URL.Query()
		b64, ok := values["dns"]
		if !ok || len(b64) != 1 {
			return nil, fmt.Errorf("no 'dns' or multiple query parameter found")
		}
		buf, err := base64.RawURLEncoding.DecodeString(b64[0])
		if err != nil {
			return nil, err
		}
		if len(buf) > dns.MaxMsgSize {
			return nil, fmt.Errorf("dns msg too big")
		}
		m := &dns.Msg{Data: buf}
		err = m.Unpack()
		if err != nil {
			return m, err
		}
		if action := MsgAcceptFunc(m); action != dns.MsgAccept {
			return nil, fmt.Errorf("dns msg unacceptable")
		}
		return m, nil

	case http.MethodPost:
		defer req.Body.Close()
		m, err := msg(req.Body)
		if err != nil {
			return m, err
		}
		if action := MsgAcceptFunc(m); action != dns.MsgAccept {
			return nil, fmt.Errorf("dns msg unacceptable")
		}
		return m, nil

	}
	return nil, fmt.Errorf("%s: %s", http.StatusText(http.StatusMethodNotAllowed), req.Method)
}

// Response converts resp to a [dns.Msg].
func Response(resp *http.Response) (*dns.Msg, error) {
	defer resp.Body.Close()
	return msg(resp.Body)
}

// msg converts the (usually the body) ReadCloser to a [dns.Msg].
func msg(r io.ReadCloser) (*dns.Msg, error) {
	buf, err := io.ReadAll(http.MaxBytesReader(nil, r, 65536))
	if err != nil {
		return nil, err
	}
	m := &dns.Msg{Data: buf}
	err = m.Unpack()
	return m, err
}

// MsgAccepFunc is the function that checks if the incoming message is valid. This function can be a noop, but
// should never be nil.
var MsgAcceptFunc = DefaultMsgAcceptFunc

// DefaultMsgAcceptFunc does everything the dns.DefaultMsgAcceptFunc does in addition to the check mandated by
// DOQ, that the Pseudo section cannot contain an TCP-KEEPALIVE option. Not other checks are performed.
func DefaultMsgAcceptFunc(m *dns.Msg) dns.MsgAcceptAction {
	// copied from dns.DefaultMsgAcceptFunc, keep in sync.
	if m.Response {
		return dns.MsgIgnore
	}
	if _, ok := dns.OpcodeToString[m.Opcode]; !ok {
		return dns.MsgRejectNotImplemented
	}
	if len(m.Question) != 1 {
		return dns.MsgReject
	}
	for _, o := range m.Pseudo {
		if _, ok := o.(*dns.TCPKEEPALIVE); ok {
			return dns.MsgReject
		}
	}
	return dns.MsgAccept
}
