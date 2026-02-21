package cookie

import (
	"context"
	"encoding/hex"
	"hash/fnv"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnsutil"
)

type Cookie struct {
	Secret string
}

func (c *Cookie) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		for _, o := range r.Pseudo {
			if cc, ok := o.(*dns.COOKIE); ok {
				if len(cc.Cookie) < 16 || len(cc.Cookie) > 40 {
					m := r.Copy()
					dnsutil.SetReply(m, r)
					m.Rcode = dns.RcodeFormatError
					m.Pack()
					io.Copy(w, m)
					return
				}

				// TODO(miek): if a longer client cookie we can actually check if this is our server cookie

				f := fnv.New64()
				io.WriteString(f, dnsutil.RemoteIP(w))
				io.WriteString(f, cc.Cookie[:16])
				io.WriteString(f, c.Secret)

				ctx = dnsctx.WithFunc(ctx, c,
					func(m *dns.Msg) *dns.Msg {
						cookie := &dns.COOKIE{Cookie: cc.Cookie[:16] + hex.EncodeToString(f.Sum(nil))}
						m.Pseudo = append(m.Pseudo, cookie)
						return m
					})

				ctx = dnsctx.WithValue(ctx, dnsctx.Key(c, dnsctx.KeyStatus), true)
				break
			}
		}

		next.ServeDNS(ctx, w, r)
	})
}
