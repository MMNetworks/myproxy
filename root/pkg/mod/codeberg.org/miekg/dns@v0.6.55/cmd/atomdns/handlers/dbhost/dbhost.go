package dbhost

import (
	"context"
	"io"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
)

type Dbhost struct {
	Path string
	ttl  uint32

	Data         map[string]dnszone.Node
	sync.RWMutex // protects Data

	ctx    context.Context
	cancel context.CancelFunc
}

func (d *Dbhost) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		// dbhosts can only answer ptr, a, and aaaa questions
		qname, qtype := dnsutil.Question(r)
		if qtype != dns.TypeA && qtype != dns.TypeAAAA && qtype != dns.TypePTR {
			next.ServeDNS(ctx, w, r)
			return
		}

		d.RLock()
		n, ok := d.Data[dnsutil.Canonical(qname)]
		d.RUnlock()
		if !ok {
			// we only own the exact name
			next.ServeDNS(ctx, w, r)
			return
		}
		m := r.Copy()
		dnsutil.SetReply(m, r)
		for _, rr := range n.RRs {
			if dns.RRToType(rr) == qtype {
				m.Answer = append(m.Answer, rr)
			}
		}

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			dnslog.PackFail(ctx, log(), Err(err))
		}
		io.Copy(w, m)
	})
}
