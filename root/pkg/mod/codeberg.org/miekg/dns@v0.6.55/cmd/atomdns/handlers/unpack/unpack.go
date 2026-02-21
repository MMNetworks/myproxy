package unpack

import (
	"context"

	"codeberg.org/miekg/dns"
)

type Unpack int

func (u *Unpack) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if err := r.Unpack(); err != nil {
			log().Debug("Unpack failure", Err(err), "zone", dns.Zone(ctx))
		}
		next.ServeDNS(ctx, w, r)
	})
}
