package url

import (
	"context"
	"io"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
)

type Url struct {
	URLs []string
	Path string

	// Zones holds all the zone this instance of Url is called for.
	Zones        map[string]*zone.Zone
	sync.RWMutex // protects Zones

	ctx    context.Context
	cancel context.CancelFunc
}

func (u *Url) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		z := u.Zone(dns.Zone(ctx))
		m := dnszone.Retrieve(z, r, nil)

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			dnslog.PackFail(ctx, log(), Err(err))
		}
		io.Copy(w, m)
	})
}

func (u *Url) Zone(origin string) *zone.Zone {
	u.RLock()
	z := u.Zones[origin]
	u.RUnlock()
	return z
}
