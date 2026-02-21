package chaos

import (
	"context"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// Chaos allows atomdns to reply to CH TXT queries and return author or version information.
// If the name starts with "authors." the authors are returned if with "version." the version is returned.
type Chaos struct {
	Version string
	Authors []string
}

func (c *Chaos) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		qclass := r.Question[0].Header().Class
		if qclass != dns.ClassCHAOS {
			next.ServeDNS(ctx, w, r)
			return
		}
		if _, ok := r.Question[0].(*dns.TXT); !ok {
			next.ServeDNS(ctx, w, r)
			return
		}

		qname := dnsutil.Canonical(r.Question[0].Header().Name)
		m := r.Copy()
		dnsutil.SetReply(m, r)
		hdr := dns.Header{Name: qname, Class: dns.ClassCHAOS}

		switch {
		case strings.HasPrefix(qname, "authors."):
			rnd := rand.New(rand.NewSource(time.Now().Unix()))
			for _, i := range rnd.Perm(len(c.Authors)) {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, TXT: rdata.TXT{Txt: []string{c.Authors[i]}}})
			}
		case strings.HasPrefix(qname, "hostname."):
			fallthrough
		case strings.HasPrefix(qname, "id."):
			hostname, err := os.Hostname()
			if err != nil {
				hostname = "localhost"
			}
			m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, TXT: rdata.TXT{Txt: []string{hostname}}}}
		default:
			m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, TXT: rdata.TXT{Txt: []string{c.Version}}}}
		}

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			dnslog.PackFail(ctx, log(), Err(err))
		}
		io.Copy(w, m)
	})
}
