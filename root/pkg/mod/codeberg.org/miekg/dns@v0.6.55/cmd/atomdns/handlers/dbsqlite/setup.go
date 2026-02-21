package dbsqlite

import (
	"path/filepath"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/jmoiron/sqlx"
	"modernc.org/sqlite"
)

func (d *Dbsqlite) Setup(co *dnsserver.Controller) error {
	d.Zones = map[string]*Zone{}
	for co.Next() {
		if !co.NextArg() {
			return co.ArgErr()
		}
		d.Path = co.Path()
		for co.NextBlock(0) {
			switch co.Val() {
			case "transfer":
				if err := d.SetupTransfer(co); err != nil {
					return err
				}
			default:
				return co.ArgErr()
			}
		}
	}
	sqlite.RegisterCollationUtf8("canonical", func(left, right string) int { return dns.CompareName(left, right) })

	co.OnStartup(func() error {
		log().Info("Startup", "initializing", filepath.Base(d.Path))
		db, err := sqlx.Open("sqlite", d.Path)
		if err != nil {
			return err
		}
		d.db = db
		for _, z := range co.Keys() {
			d.Zones[dnsutil.Canonical(z)] = &Zone{db: db, labels: dnsutil.Labels(z), origin: dnsutil.Canonical(z)}
		}
		_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS rrs (
name  VARCHAR(255),
type  VARCHAR(10),
data  VARCHAR(65535),
ttl   INTEGER,
UNIQUE (name, type, data)
);
	`)
		return err
	})
	co.OnStartup(func() error {
		log().Info("Startup", "path", filepath.Base(d.Path), "records", d.Count(), "zones", strings.Join(d.Origins(), ","))
		return nil
	})
	co.OnShutdown(func() error {
		log().Info("Shutdown", "path", filepath.Base(d.Path))
		d.db.Close()
		return nil
	})

	return nil
}
