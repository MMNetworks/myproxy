package dbhost

import (
	"context"
	"path/filepath"
	"strconv"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (d *Dbhost) Setup(co *dnsserver.Controller) error {
	d.Path, d.ttl = "/etc/hosts", 3600
	d.ctx, d.cancel = context.WithCancel(context.Background())
	for co.Next() {
		paths := co.RemainingPaths()
		if len(paths) > 1 {
			return co.ArgErr()
		}
		if len(paths) == 1 {
			d.Path = paths[0]
		}

		if co.NextBlock(0) {
			switch co.Val() {
			case "ttl":
				args := co.RemainingArgs()
				if len(args) == 0 {
					return co.PropEmptyErr("ttl")
				}
				ttl, err := strconv.ParseUint(args[0], 10, 32)
				if err != nil {
					return co.PropErr(err)
				}
				d.ttl = uint32(ttl)

			default:
				return co.PropErr()
			}
		}
	}

	co.OnStartup(func() error {
		log().Info("Startup", "reload", filepath.Base(d.Path))
		if err := d.Load(); err != nil {
			return co.Err(err.Error())
		}
		return d.Reload()
	})

	co.OnShutdown(func() error {
		log().Info("Shutdown", "reload", filepath.Base(d.Path))
		d.cancel()
		return nil
	})

	return nil
}
