package id

import (
	"context"
	"crypto/rand"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
)

type Id int

func (i *Id) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		ctx = dnsctx.WithValue(ctx, dnsctx.Key(i, "id"), rand.Text())
		next.ServeDNS(ctx, w, r)
	})
}
