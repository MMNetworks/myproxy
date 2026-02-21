package nsid

import (
	"encoding/hex"
	"os"
	"strings"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (n *Nsid) Setup(co *dnsserver.Controller) error {
	data, err := os.Hostname()
	if err != nil {
		data = "localhost"
	}
	for co.Next() {
		args := co.RemainingArgs()
		if len(args) > 0 {
			data = strings.Join(args, " ")
		}
	}
	n.Data = hex.EncodeToString([]byte(data))
	return nil
}
