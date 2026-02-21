package dnstest

import (
	"net"
	"net/netip"

	"codeberg.org/miekg/dns"
)

const port = 40212

// ResponseWriter is useful for writing tests. It uses some fixed values for the client. The
// remote will always be 198.51.100.1 ([IPv4], see RFC 5737) and port 40212.
// The local address is always 127.0.0.1 and port 53. See [ResponseWriter6] for an IPv6 version.
type ResponseWriter struct {
	TCP bool // if TCP is true, this is a TCP connection instead of an UDP one.
}

// ResponseWriter6 returns fixed client and remote address in IPv6.  The remote
// address is always and 2001:db8::1 ([IPv6], see RFC 5156) and port 40212.
// The local address is always ::1 and port 53. See [ResponseWriter] for an IPv4 version.
type ResponseWriter6 struct {
	ResponseWriter
}

// IP addresses for documentation and test purposes.
var (
	IPv4 = netip.MustParseAddr("198.51.100.1") // RFC 5737
	IPv6 = netip.MustParseAddr("2001:db8::1")  // RFC 5156

	localhostv4 = net.ParseIP("127.0.0.1")
	localhostv6 = net.ParseIP("::1")
)

func (t *ResponseWriter6) LocalAddr() net.Addr {
	if t.TCP {
		return &net.TCPAddr{IP: localhostv6, Port: 53}
	}
	return &net.UDPAddr{IP: localhostv6, Port: 53}
}

func (t *ResponseWriter6) RemoteAddr() net.Addr {
	if t.TCP {
		return &net.TCPAddr{IP: IPv6.AsSlice(), Port: port}
	}
	return &net.UDPAddr{IP: IPv6.AsSlice(), Port: port}
}

func (t *ResponseWriter) LocalAddr() net.Addr {
	if t.TCP {
		return &net.TCPAddr{IP: localhostv4, Port: 53}
	}
	return &net.UDPAddr{IP: localhostv4, Port: 53}
}

func (t *ResponseWriter) RemoteAddr() net.Addr {
	if t.TCP {
		return &net.TCPAddr{IP: IPv4.AsSlice(), Port: port}
	}
	return &net.UDPAddr{IP: IPv4.AsSlice(), Port: port}
}

func (t *ResponseWriter) Write(buf []byte) (int, error) { return len(buf), nil }
func (t *ResponseWriter) Conn() net.Conn                { return nil }
func (t *ResponseWriter) Session() *dns.Session         { return nil }
func (t *ResponseWriter) Close() error                  { return nil }
func (t *ResponseWriter) Hijack()                       {}
