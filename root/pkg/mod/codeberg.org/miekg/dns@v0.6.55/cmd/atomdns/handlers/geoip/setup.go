package geoip

import (
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"github.com/oschwald/geoip2-golang/v2"
)

func (g *Geoip) Setup(co *dnsserver.Controller) (err error) {
	for co.Next() {
		for co.NextBlock(0) {
			val := co.Val()
			paths := co.RemainingPaths()
			if len(paths) == 0 {
				return co.PropEmptyErr("dbfile")
			}
			if len(paths) > 2 {
				return co.ArgErr()
			}
			switch val {
			case "city":
				if g.City, err = geoip2.Open(paths[0]); err != nil {
					return err
				}
				if len(paths) == 2 {
					if g.City6, err = geoip2.Open(paths[1]); err != nil {
						return err
					}
				}
			case "asn":
				if g.Asn, err = geoip2.Open(paths[0]); err != nil {
					return err
				}
				if len(paths) == 2 {
					if g.Asn6, err = geoip2.Open(paths[1]); err != nil {
						return err
					}
				}
			}
		}
	}
	if g.City == nil && g.Asn == nil {
		return co.Err("either city or asn must be configured")
	}
	return nil
}
