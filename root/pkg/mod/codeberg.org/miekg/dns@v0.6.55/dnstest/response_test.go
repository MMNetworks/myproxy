package dnstest

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func TestResponseWriter(t *testing.T) {
	m := new(dns.Msg)
	m.Question = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: "example.org.", Class: dns.ClassINET}}}

	rec := NewRecorder(&ResponseWriter{})
	h := reflect{}

	h.ServeDNS(context.TODO(), rec, m)
	rec.Msg.Unpack()
	if x := rec.Msg.Answer[0].(*dns.A).Addr.String(); x != IPv4.String() {
		t.Errorf("expected %s in answer, got %s", IPv4.String(), x)
	}
}

type reflect struct{}

func (h reflect) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
	r.Unpack()
	m := new(dns.Msg)
	dnsutil.SetReply(m, r)

	ip := w.RemoteAddr().(*net.UDPAddr)
	str := "Port: " + strconv.Itoa(ip.Port) + " (udp)"

	a := &dns.A{Hdr: dns.Header{Name: "example.org.", Class: dns.ClassINET}, A: rdata.A{Addr: ip.AddrPort().Addr()}}
	t := &dns.TXT{Hdr: dns.Header{Name: "example.org.", Class: dns.ClassINET}, TXT: rdata.TXT{Txt: []string{str}}}

	m.Answer = append(m.Answer, a)
	m.Extra = append(m.Extra, t)

	io.Copy(w, m)
}
