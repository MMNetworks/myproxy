package dbfile

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

func (d *Dbfile) Setup(co *dnsserver.Controller) error {
	d.Zones = map[string]*zone.Zone{}
	d.ctx, d.cancel = context.WithCancel(context.Background())

	if co.Next() {
		if !co.Next() {
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
	if len(co.Keys()) > 1 && len(d.From.IPs) > 0 {
		return co.Errf("when transferring from, there can only be a single origin, got: %s", strings.Join(co.Keys(), ", "))
	}

	for _, z := range co.Keys() {
		d.Zones[dnsutil.Canonical(z)] = zone.New(z, d.Path)
	}
	co.OnStartup(func() error {
		log().Info("Startup", "reload", filepath.Base(d.Path))
		d.RLock()
		zones := maps.Values(d.Zones)
		d.RUnlock()
		for z := range zones {
			alog := log().With(slog.String("zone", z.Origin()), slog.String("file", filepath.Base(z.Path)))
			_, err := os.Stat(z.Path)
			if errors.Is(err, os.ErrNotExist) {
				alog.Warn("Waiting for zone to appear")
				continue
			}
			if err := z.Load(); err != nil {
				return co.Err(err.Error())
			}
		}
		return d.Reload()
	})
	if d.From != nil && len(d.From.IPs) > 0 {
		co.OnStartup(func() error {
			d.RLock()
			zones := maps.Values(d.Zones)
			d.RUnlock()
			for z := range zones {
				log().Info("Startup", "retransfer", z.Origin(), "file", filepath.Base(z.Path))

				apex := z.Apex()
				serial := uint32(0)
				if apex != nil {
					for _, rr := range apex.RRs {
						if s, ok := rr.(*dns.SOA); ok {
							serial = s.Serial
							break
						}
					}
				}
				if !d.From.AvailableFrom(z.Origin(), serial) {
					continue
				}

				err := d.TransferIn(z.Origin())
				if err != nil {
					alog := log().With(slog.String("zone", z.Origin()), slog.String("file", filepath.Base(z.Path)))
					alog.Error("Failed to transfer", Err(err))
				}
				break
			}
			return d.Retransfer()
		})
	}
	if d.To != nil && len(d.To.IPs) > 0 {
		co.OnStartup(func() error {
			d.RLock()
			zones := maps.Values(d.Zones)
			d.RUnlock()
			for z := range zones {
				go func() {
					N := time.Duration(rand.IntN(20)) + 10
					log().Info("Startup", "notifying", z.Origin(), "file", filepath.Base(d.Path), slog.Duration("after", N*time.Second))
					time.Sleep(N * time.Second)
					d.To.Notify(z.Origin())
				}()
			}
			return nil
		})
	}

	co.OnShutdown(func() error {
		log().Info("Shutdown", "reload", filepath.Base(d.Path))
		d.cancel()
		return nil
	})
	if d.From != nil && len(d.From.IPs) > 0 {
		co.OnShutdown(func() error {
			log().Info("Shutdown", "retransfer", filepath.Base(d.Path))
			d.cancel()
			return nil
		})
	}

	return nil
}
