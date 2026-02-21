package global

import (
	"fmt"
	"runtime"
	"strconv"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/num"
)

type Limits struct {
	MaxTCPQueries int
	MaxInflight   int
	Servers       int
}

func (g *Global) SetupLimits(d *conffile.Dispenser) (Limits, error) {
	l := Limits{MaxTCPQueries: dns.MaxTCPQueries, Servers: -1, MaxInflight: 1024}
	var err error
	for d.NextBlock(1) {
		switch d.Val() {
		case "tcp":
			exprs := d.RemainingArgs()
			if len(exprs) != 1 {
				return l, d.PropErr(fmt.Errorf("need single expression"))
			}
			if l.MaxTCPQueries, err = strconv.Atoi(exprs[0]); err != nil {
				return l, d.PropErr(err)
			}
		case "run":
			exprs := d.RemainingArgs()
			if len(exprs) != 1 {
				return l, d.PropErr(fmt.Errorf("need single expression"))
			}
			if l.Servers, err = num.CPU(exprs[0]); err != nil {
				return l, d.PropErr(err)
			}
			if l.Servers > runtime.NumCPU()*1024 {
				return l, d.PropErr(fmt.Errorf("should be smaller than %d: %d", runtime.NumCPU()*1024, l.Servers))
			}
		case "inflight":
			exprs := d.RemainingArgs()
			if len(exprs) != 1 {
				return l, d.PropErr(fmt.Errorf("need single expression"))
			}
			if l.MaxInflight, err = num.CPU(exprs[0]); err != nil {
				return l, d.PropErr(err)
			}
		default:
			return l, d.ArgErr()
		}
	}
	return l, nil
}
