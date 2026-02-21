package url

import (
	"log/slog"
	"maps"
	"path/filepath"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
)

// Reload launches a reload routine that listens for _write_ events to the zone files.
func (u *Url) Reload() error {
	return dnszone.Watch(u.ctx, u.Path, func() {
		u.RLock()
		zones := maps.Values(u.Zones)
		u.RUnlock()

		for z := range zones {
			alog := log().With(slog.String("zone", z.Origin()), slog.String("file", filepath.Base(u.Path)))
			z1 := zone.New(z.Origin(), u.Path)
			if err := z1.Load(); err != nil {
				alog.Error("Failed to reload", Err(err))
				continue
			}
			u.Lock()
			u.Zones[z.Origin()] = z1
			u.Unlock()
			alog.Info("Successful reload")
		}
	})
}
