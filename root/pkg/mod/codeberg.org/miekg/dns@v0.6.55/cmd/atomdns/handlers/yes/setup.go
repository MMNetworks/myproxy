package yes

import (
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

func (y *Yes) Setup(co *dnsserver.Controller) error {
	if co.Next() {
		for co.NextBlock(0) {
			switch co.Val() {
			case "caa":
				args := co.RemainingArgs()
				if len(args) == 0 {
					return co.PropEmptyErr("caa")
				}
				y.Caa = append(y.Caa, strings.TrimSpace(args[0]))
			case "ns":
				args := co.RemainingArgs()
				if len(args) == 0 {
					return co.PropEmptyErr("ns")
				}
				for _, arg := range args {
					y.Ns = dnsutil.Canonical(arg)
				}
			default:
				return co.PropErr()
			}
		}
	}
	if len(y.Caa) == 0 {
		return co.PropEmptyErr("caa")
	}
	if y.Ns == "" {
		return co.PropEmptyErr("ns")
	}
	return nil
}
