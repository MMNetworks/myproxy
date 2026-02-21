package any

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

type Any int

func (a *Any) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if _, ok := r.Question[0].(*dns.ANY); !ok {
			next.ServeDNS(ctx, w, r)
			return
		}

		m := r.Copy()
		dnsutil.SetReply(m, r)
		hdr := dns.Header{Name: r.Question[0].Header().Name, TTL: 8482, Class: dns.ClassINET}
		m.Answer = []dns.RR{&dns.HINFO{Hdr: hdr, HINFO: rdata.HINFO{Cpu: "ANY obsoleted", Os: "See RFC 8482"}}}

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			dnslog.PackFail(ctx, log(), Err(err))
		}
		io.Copy(w, m)
	})
}
