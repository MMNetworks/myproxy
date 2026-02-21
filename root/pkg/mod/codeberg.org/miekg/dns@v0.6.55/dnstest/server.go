package dnstest

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
	"codeberg.org/miekg/dns/internal/bin"
)

// Server returns a new running (UDP) [dns.Server]. The returned cancel function shuts down the server. Any options should
// be set by opts. The returned strings have the actual listening addresses, this is useful in case of listening on the
// wildcard port. If no network is configured via the opts functions, UDP is assumed.
func Server(addr string, opts ...func(*dns.Server)) (cancel func(), listening string, err error) {
	s := dns.NewServer()
	s.Addr = addr
	wait := make(chan error, 1)
	s.NotifyStartedFunc = func(context.Context) { wait <- nil }
	s.MsgInvalidFunc = func(m *dns.Msg, err error) {
		log.Printf("Invalid message: %s - %T\n%s", err, err, bin.Dump(m.Data))
	}
	cancel = func() { s.Shutdown(context.TODO()) }

	for _, opt := range opts {
		opt(s)
	}

	if s.Net == "" {
		s.Net = "udp"
	}

	go func() {
		err := s.ListenAndServe()
		if err != nil {
			wait <- err
		}
	}()
	if err := <-wait; err != nil {
		return nil, "", err
	}

	if s.PacketConn != nil {
		listening = s.PacketConn.LocalAddr().String()
	}
	if s.Listener != nil {
		listening = s.Listener.Addr().String()
	}
	return cancel, listening, nil
}

// UDPServer calls [Server] with the option to start a UDP server.
func UDPServer(addr string, opts ...func(*dns.Server)) (func(), string, error) {
	opt := func(s *dns.Server) { s.Net = "udp" }
	opts = append(opts, opt)
	cancel, listen, err := Server(addr, opts...)
	return cancel, listen, err
}

// TCPServer calls [Server] with the option to start a TCP server.
func TCPServer(addr string, opts ...func(*dns.Server)) (func(), string, error) {
	opt := func(s *dns.Server) { s.Net = "tcp" }
	opts = append(opts, opt)
	cancel, listen, err := Server(addr, opts...)
	return cancel, listen, err
}

// TLSServer calls [Server] with a TLS configuration. The NextProtos field is set to "dot".
func TLSServer(addr string, opts ...func(*dns.Server)) (func(), string, error) {
	tlsopt := func(s *dns.Server) {
		s.TLSConfig = TLSConfig()
		s.TLSConfig.NextProtos = dns.NextProtos
	}
	opts = append(opts, tlsopt)
	return TCPServer(addr, opts...)
}

// TLSConfig returns the testing TLS config. The returned config has InsecureSkipVerify set to true, as the
// certificate itself is expired.
func TLSConfig() *tls.Config {
	cert, _ := tls.X509KeyPair([]byte(certPEMBlock), []byte(keyPEMBlock))
	return &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
}

// HTTPServer returns a new running (DOH) server. See [Server] for the documentation on the returned
// values. If the TLSConfig in the server is set (via the opts functions) a TLS capable server is started.
func HTTPServer(addr string, opts ...func(*http.Server)) (func(), string, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", err
	}

	hmux := http.NewServeMux()
	hh := &handler{}
	hmux.Handle("/dns-query", hh)
	hs := &http.Server{Addr: addr, Handler: hmux, ReadTimeout: 5 * time.Second}

	for _, opt := range opts {
		opt(hs)
	}

	if hs.TLSConfig != nil {
		l = tls.NewListener(l, hs.TLSConfig)
	}

	// assume this works
	go func() {
		hs.Serve(l)
	}()

	cancel := func() { hs.Shutdown(context.TODO()) }
	return cancel, l.Addr().String(), nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m, err := dnshttp.Request(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hw := dnshttp.NewResponseWriter(w, r, r.Context().Value(http.LocalAddrContextKey).(net.Addr))
	dns.DefaultServeMux.ServeDNS(context.Background(), hw, m)
}

type handler struct{}

const (
	// certPEMBlock is a X509 data used to test TLS servers (used with tls.X509KeyPair)
	certPEMBlock = `-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIRAJFYMkcn+b8dpU15wjf++GgwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjAxMDgxMjAzNTNaFw0xNzAxMDcxMjAz
NTNaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDXjqO6skvP03k58CNjQggd9G/mt+Wa+xRU+WXiKCCHttawM8x+slq5
yfsHCwxlwsGn79HmJqecNqgHb2GWBXAvVVokFDTcC1hUP4+gp2gu9Ny27UHTjlLm
O0l/xZ5MN8tfKyYlFw18tXu3fkaPyHj8v/D1RDkuo4ARdFvGSe8TqisbhLk2+9ow
xfIGbEM9Fdiw8qByC2+d+FfvzIKz3GfQVwn0VoRom8L6NBIANq1IGrB5JefZB6nv
DnfuxkBmY7F1513HKuEJ8KsLWWZWV9OPU4j4I4Rt+WJNlKjbD2srHxyrS2RDsr91
8nCkNoWVNO3sZq0XkWKecdc921vL4ginAgMBAAGjVDBSMA4GA1UdDwEB/wQEAwIC
pDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQT
MBGCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAGcU3iyLBIVZj
aDzSvEDHUd1bnLBl1C58Xu/CyKlPqVU7mLfK0JcgEaYQTSX6fCJVNLbbCrcGLsPJ
fbjlBbyeLjTV413fxPVuona62pBFjqdtbli2Qe8FRH2KBdm41JUJGdo+SdsFu7nc
BFOcubdw6LLIXvsTvwndKcHWx1rMX709QU1Vn1GAIsbJV/DWI231Jyyb+lxAUx/C
8vce5uVxiKcGS+g6OjsN3D3TtiEQGSXLh013W6Wsih8td8yMCMZ3w8LQ38br1GUe
ahLIgUJ9l6HDguM17R7kGqxNvbElsMUHfTtXXP7UDQUiYXDakg8xDP6n9DCDhJ8Y
bSt7OLB7NQ==
-----END CERTIFICATE-----`

	// keyPEMBlock is a X509 data used to test TLS servers (used with tls.X509KeyPair)
	keyPEMBlock = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA146jurJLz9N5OfAjY0IIHfRv5rflmvsUVPll4iggh7bWsDPM
frJaucn7BwsMZcLBp+/R5iannDaoB29hlgVwL1VaJBQ03AtYVD+PoKdoLvTctu1B
045S5jtJf8WeTDfLXysmJRcNfLV7t35Gj8h4/L/w9UQ5LqOAEXRbxknvE6orG4S5
NvvaMMXyBmxDPRXYsPKgcgtvnfhX78yCs9xn0FcJ9FaEaJvC+jQSADatSBqweSXn
2Qep7w537sZAZmOxdeddxyrhCfCrC1lmVlfTj1OI+COEbfliTZSo2w9rKx8cq0tk
Q7K/dfJwpDaFlTTt7GatF5FinnHXPdtby+IIpwIDAQABAoIBAAJK4RDmPooqTJrC
JA41MJLo+5uvjwCT9QZmVKAQHzByUFw1YNJkITTiognUI0CdzqNzmH7jIFs39ZeG
proKusO2G6xQjrNcZ4cV2fgyb5g4QHStl0qhs94A+WojduiGm2IaumAgm6Mc5wDv
ld6HmknN3Mku/ZCyanVFEIjOVn2WB7ZQLTBs6ZYaebTJG2Xv6p9t2YJW7pPQ9Xce
s9ohAWohyM4X/OvfnfnLtQp2YLw/BxwehBsCR5SXM3ibTKpFNtxJC8hIfTuWtxZu
2ywrmXShYBRB1WgtZt5k04bY/HFncvvcHK3YfI1+w4URKtwdaQgPUQRbVwDwuyBn
flfkCJECgYEA/eWt01iEyE/lXkGn6V9lCocUU7lCU6yk5UT8VXVUc5If4KZKPfCk
p4zJDOqwn2eM673aWz/mG9mtvAvmnugaGjcaVCyXOp/D/GDmKSoYcvW5B/yjfkLy
dK6Yaa5LDRVYlYgyzcdCT5/9Qc626NzFwKCZNI4ncIU8g7ViATRxWJ8CgYEA2Ver
vZ0M606sfgC0H3NtwNBxmuJ+lIF5LNp/wDi07lDfxRR1rnZMX5dnxjcpDr/zvm8J
WtJJX3xMgqjtHuWKL3yKKony9J5ZPjichSbSbhrzfovgYIRZLxLLDy4MP9L3+CX/
yBXnqMWuSnFX+M5fVGxdDWiYF3V+wmeOv9JvavkCgYEAiXAPDFzaY+R78O3xiu7M
r0o3wqqCMPE/wav6O/hrYrQy9VSO08C0IM6g9pEEUwWmzuXSkZqhYWoQFb8Lc/GI
T7CMXAxXQLDDUpbRgG79FR3Wr3AewHZU8LyiXHKwxcBMV4WGmsXGK3wbh8fyU1NO
6NsGk+BvkQVOoK1LBAPzZ1kCgYEAsBSmD8U33T9s4dxiEYTrqyV0lH3g/SFz8ZHH
pAyNEPI2iC1ONhyjPWKlcWHpAokiyOqeUpVBWnmSZtzC1qAydsxYB6ShT+sl9BHb
RMix/QAauzBJhQhUVJ3OIys0Q1UBDmqCsjCE8SfOT4NKOUnA093C+YT+iyrmmktZ
zDCJkckCgYEAndqM5KXGk5xYo+MAA1paZcbTUXwaWwjLU+XSRSSoyBEi5xMtfvUb
7+a1OMhLwWbuz+pl64wFKrbSUyimMOYQpjVE/1vk/kb99pxbgol27hdKyTH1d+ov
kFsxKCqxAnBVGEWAvVZAiiTOxleQFjz5RnL0BQp9Lg2cQe+dvuUmIAA=
-----END RSA PRIVATE KEY-----`
)
