package cookie

import (
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (c *Cookie) Setup(co *dnsserver.Controller) error {
	for co.Next() {
		args := co.RemainingArgs()
		if len(args) == 0 {
			return co.PropEmptyErr("secret")
		}
		c.Secret = strings.Join(args, " ")
	}
	return nil
}
