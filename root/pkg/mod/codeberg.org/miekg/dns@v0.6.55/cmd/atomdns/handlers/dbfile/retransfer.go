package dbfile

import (
	"log/slog"
	"path/filepath"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
)

func (d *Dbfile) Retransfer() error {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ticker.C:
				z1 := &zone.Zone{}
				d.RLock()
				for _, z := range d.Zones {
					z1 = z
					break
				}
				d.RUnlock()
				apex := z1.Apex()
				serial := uint32(0)
				for _, rr := range apex.RRs {
					if s, ok := rr.(*dns.SOA); ok {
						serial = s.Serial
						break
					}
				}
				if !d.From.AvailableFrom(z1.Origin(), serial) {
					continue
				}

				err := d.TransferIn(z1.Origin())
				if err != nil {
					alog := log().With(slog.String("zone", z1.Origin()), slog.String("file", filepath.Base(z1.Path)))
					alog.Error("Failed to transfer", Err(err))
					continue
				}
			case <-d.ctx.Done():
				return
			}
		}
	}()

	return nil
}
