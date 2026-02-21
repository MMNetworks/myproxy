package metrics

import (
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (m *Metrics) Setup(co *dnsserver.Controller) error {
	m.N = co.Global.MetricsN
	if co.Next() {
		if !co.NextArg() {
			return nil
		}
		if co.Val() == "disable" || co.Val() == "enable" || co.Val() == "" {
			if co.Val() == "disable" {
				m.disable = true
			}
			return nil
		}
	}
	return nil
}
