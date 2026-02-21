package refuse

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/dnsutil"
)

// Refuse is a handler that returns refused, it use is to be the final handler, that is reached, returns
// refused.
type Refuse int

func (r *Refuse) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := &dns.Msg{Data: r.Data}
		dnsutil.SetReply(m, r)
		m.Rcode = dns.RcodeRefused

		if err := m.Pack(); err != nil {
			dnslog.PackFail(ctx, log(), Err(err))
		}
		io.Copy(w, m)
	})
}
