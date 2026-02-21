package dbsqlite

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

type Dbsqlite struct {
	Path string

	db    *sqlx.DB
	Zones map[string]*Zone // read-only after startup

	To *dbfile.Transfer
}

func (d *Dbsqlite) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if _, qtype := dnsutil.Question(r); qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
			d.HandlerFuncTransfer(ctx, w, r)
			return
		}

		z := d.Zones[dns.Zone(ctx)]
		m := dnszone.Retrieve(z, r, nil)
		m.Data = r.Data

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			dnslog.PackFail(ctx, log(), Err(err))
		}
		io.Copy(w, m)
	})
}

func (d *Dbsqlite) Count() int {
	ints := []int{}
	if err := d.db.Select(&ints, "SELECT COUNT(*) FROM rrs"); err != nil {
		return 0
	}
	return ints[0]
}

func (d *Dbsqlite) Origins() []string {
	origins := []string{}
	d.db.Select(&origins,
		`SELECT DISTINCT name FROM rrs r1
WHERE NOT EXISTS (
  SELECT 1 FROM rrs r2
  WHERE r1.name LIKE '%.' || r2.name AND r1.name != r2.name
) ORDER BY name COLLATE canonical`)
	return origins
}
