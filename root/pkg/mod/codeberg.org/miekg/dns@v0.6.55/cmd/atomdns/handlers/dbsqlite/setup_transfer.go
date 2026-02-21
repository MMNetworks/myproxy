package dbsqlite

import (
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

// Setup transfer handles the transfer options.
func (d *Dbsqlite) SetupTransfer(co *dnsserver.Controller) (err error) {
	d.To = &dbfile.Transfer{}
	for co.NextBlock(1) {
		switch co.Val() {
		case "}":
			return nil
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
					d.To.Sources, err = co.RemainingAddrs()
					if err != nil {
						return co.PropErr(err)
					}
					if len(d.To.Sources) == 0 {
						return co.ArgErr()
					}
				}
			}

		default:
			return co.SyntaxErr("expected 'from', got: " + co.Val())
		}
	}
	return nil
}
