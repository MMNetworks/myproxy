package acl

import (
	"context"
	"io"
	"log/slog"
	"strconv"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsmetrics"
	"codeberg.org/miekg/dns/dnsutil"
)

// Acl enforces access control policies on DNS queries.
type Acl struct {
	Rules []rule

	// metrics \N option
	i uint64
	N uint64
}

func (a *Acl) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		fam := dnsutil.Family(w)
		if x := dnsctx.Addr(ctx, "etc/address"); x.IsValid() {
			log().Debug("Using 'ecs/address'", slog.String("address", x.String()))
			fam = dnsutil.IPv6Family
			if x.Is4() {
				fam = dnsutil.IPv4Family
			}
		}

	Rules:
		for _, rule := range a.Rules {
			action := match(ctx, rule.policies, w, r)
			switch action {
			case dns.MsgAccept:
				break Rules
			case dns.MsgIgnore:
				if dnsmetrics.Should(&a.i, a.N) {
					RequestsDrop.WithLabelValues(dns.Zone(ctx), dnsutil.Network(w), strconv.Itoa(fam)).Inc()
				}
				return
			case dns.MsgReject:
				m := r.Copy()
				dnsutil.SetReply(m, r)
				m.Data = r.Data
				m.Rcode = dns.RcodeRefused
				m.Pseudo = []dns.RR{&dns.EDE{InfoCode: dns.ExtendedErrorBlocked}}

				m.Pack()
				io.Copy(w, m)

				if dnsmetrics.Should(&a.i, a.N) {
					RequestsBlock.WithLabelValues(dns.Zone(ctx), dnsutil.Network(w), strconv.Itoa(fam)).Inc()
				}
				return
			case MsgFilter:
				m := r.Copy()
				dnsutil.SetReply(m, r)
				m.Data = r.Data
				m.Rcode = dns.RcodeRefused
				m.Pseudo = []dns.RR{&dns.EDE{InfoCode: dns.ExtendedErrorFiltered}}

				m.Pack()
				io.Copy(w, m)

				if dnsmetrics.Should(&a.i, a.N) {
					RequestsFilter.WithLabelValues(dns.Zone(ctx), dnsutil.Network(w), strconv.Itoa(fam)).Inc()
				}
				return
			}
		}

		if dnsmetrics.Should(&a.i, a.N) {
			RequestsAllow.WithLabelValues(dns.Zone(ctx), dnsutil.Network(w), strconv.Itoa(fam)).Inc()
		}
		next.ServeDNS(ctx, w, r)
	})
}
