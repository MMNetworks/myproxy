package whoami

import (
	"context"
	"io"
	"net"
	"net/netip"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/pkg/pool"
	"codeberg.org/miekg/dns/rdata"
)

type Whoami int

func (w *Whoami) HandlerFunc(_ dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := r.Copy()
		dnsutil.SetReply(m, r)

		var ip netip.Addr
		switch a := w.RemoteAddr().(type) {
		case *net.UDPAddr:
			ip, _ = netip.AddrFromSlice(a.IP)
		case *net.TCPAddr:
			ip, _ = netip.AddrFromSlice(a.IP)
		}
		if x := dnsctx.Addr(ctx, "ecs/addr"); x.IsValid() {
			ip = x
		}
		if ip.Is4In6() {
			ip = netip.AddrFrom4(ip.As4())
		}

		var rr dns.RR
		if ip.Is4() {
			rr = &dns.A{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, A: rdata.A{Addr: ip}}
		} else {
			rr = &dns.AAAA{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, AAAA: rdata.AAAA{Addr: ip}}
		}

		sb := builderPool.Get()
		sb.WriteString("Port: ")
		sb.WriteString(dnsutil.RemotePort(w))
		sb.WriteString(" (")
		sb.WriteString(dnsutil.Network(w))
		sb.WriteString(")")
		t := &dns.TXT{Hdr: dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET}, TXT: rdata.TXT{Txt: []string{sb.String()}}}
		builderPool.Put(sb)

		switch r.Question[0].(type) {
		case *dns.TXT:
			m.Answer = append(m.Answer, t)
			m.Extra = append(m.Extra, rr)
		case *dns.AAAA, *dns.A:
			m.Answer = append(m.Answer, rr)
			m.Extra = append(m.Extra, t)
		default:
			m.Rcode = dns.RcodeRefused
		}

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			dnslog.PackFail(ctx, log(), Err(err))
		}
		io.Copy(w, m)
	})
}

var builderPool = pool.NewBuilder()
