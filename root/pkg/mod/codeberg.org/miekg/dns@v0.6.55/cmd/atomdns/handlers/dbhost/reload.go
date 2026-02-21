package dbhost

import (
	"log/slog"
	"path/filepath"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
)

// Reload launches a reload routine that listens for _write_ events to the hosts file.
func (d *Dbhost) Reload() error {
	return dnszone.Watch(d.ctx, d.Path, func() {
		alog := log().With(slog.String("path", filepath.Base(d.Path)))
		if err := d.Load(); err != nil {
			alog.Error("Failed to reload", Err(err))
			return
		}
		alog.Info("Successful reload")
	})
}
