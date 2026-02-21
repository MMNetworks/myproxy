package chaos

import (
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

const Version = "Served by atomdns, https://atomdns.miek.nl"

func (c *Chaos) Setup(co *dnsserver.Controller) error {
	c.Version = Version
	if co.Next() {
		args := co.RemainingArgs()
		if len(args) > 1 {
			return co.ArgErr()
		}
		if len(args) == 1 {
			c.Version = args[0]
		}
		authors := []string{}
		for co.NextBlock(0) {
			switch co.Val() {
			case "authors":
				for co.NextBlock(1) {
					authors = append(authors, strings.TrimSpace(co.Val()))
					for co.NextLine() {
						if co.Val() == "}" {
							break
						}
						authors = append(authors, strings.TrimSpace(co.Val()))
					}
				}
			default:
				return co.PropErr()
			}
		}
		if len(authors) > 0 {
			c.Authors = authors
		}
	}
	return nil
}
