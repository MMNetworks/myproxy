package dbfile

import (
	"log/slog"
	"maps"
	"path/filepath"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
)

// Reload launches a reload routine that listens for _write_ events to the zone files.
func (d *Dbfile) Reload() error {
	return dnszone.Watch(d.ctx, d.Path, func() {
		d.RLock()
		zones := maps.Values(d.Zones)
		d.RUnlock()

		for z := range zones {
			alog := log().With(slog.String("zone", z.Origin()), slog.String("file", filepath.Base(d.Path)))
			z1 := zone.New(z.Origin(), d.Path)
			if err := z1.Load(); err != nil {
				alog.Error("Failed to reload", Err(err))
				continue
			}
			d.Lock()
			d.Zones[z.Origin()] = z1
			d.Unlock()
			alog.Info("Successful reload")
			if d.To != nil && len(d.To.IPs) > 0 {
				go d.To.Notify(z.Origin())
			}
		}
	})
}
