package dbfile

import (
	"fmt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnsutil"
)

// Setup transfer handles the transfer options.
func (d *Dbfile) SetupTransfer(co *dnsserver.Controller) (err error) {
	d.To, d.From = &Transfer{}, &Transfer{}
	for co.NextBlock(1) {
		switch co.Val() {
		case "}":
			return nil
		case "from":
			d.From.IPs, err = co.RemainingAddrs()
			if err != nil {
				return co.PropErr(err)
			}
			if len(d.From.IPs) == 0 {
				co.ArgErr()
			}

			for co.NextBlock(2) {
				switch co.Val() {
				case "key":
					if err := d.From.SetupTransferTSIG(co); err != nil {
						return err
					}
				}
			}

		case "to":
			d.To.IPs, _ = co.RemainingAddrs()

			for co.NextBlock(2) {
				switch co.Val() {
				case "key":
					if err := d.To.SetupTransferTSIG(co); err != nil {
						return err
					}
				case "notify":
					d.To.Notifies, err = co.RemainingAddrs()
					if err != nil {
						return co.PropErr(err)
					}
					if len(d.To.Notifies) == 0 {
						return co.ArgErr()
					}
				case "source":
					d.To.Sources, err = co.RemainingIPs()
					if err != nil {
						return co.PropErr(err)
					}
					if len(d.To.Sources) == 0 || len(d.To.Sources) > 2 {
						return co.ArgErr()
					}
				}
			}

		default:
			return co.SyntaxErr("expected 'to' or 'from', got: " + co.Val())
		}
	}
	return nil
}

// SetuptransferTSIG handles the transfer tsig option.
func (t *Transfer) SetupTransferTSIG(co *dnsserver.Controller) error {
	// we're called after key ....
	args := co.RemainingArgs()
	if len(args) != 3 {
		return co.ArgErr()
	}
	if !dnsutil.IsName(args[0]) {
		return co.PropErr(fmt.Errorf("name %q is not a domain name", args[0]))
	}
	if !dnsutil.IsName(args[1]) {
		return co.PropErr(fmt.Errorf("algorithm %s is not a domain name", args[0]))
	}
	t.TSIG = dns.NewTSIG(dnsutil.Canonical(args[0]), dnsutil.Canonical(args[1]), 0)
	t.TSIGSecret = args[2]
	return nil
}
