package zone

import (
	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
)

// Walk walks the zone and calls fn on each element found, as long as f returns true the walk is continued.
// The order of the walk is ascending order: from apex to longest child.
func (z *Zone) Walk(fn func(*dnszone.Node) bool) { z.Tree.Scan(fn) }

// AuthoritativeWalk walks the the zone, but keeps track of authoritative names and call fn auth a boolean
// indicating is the name is considered that.
func (z *Zone) AuthoritativeWalk(fn func(*dnszone.Node, bool) bool) {
	delegated := map[string]struct{}{}

	z.Walk(func(n *dnszone.Node) bool {
		if len(n.Name) > len(z.Origin()) { // apex also has NSes, if we add those the entire zone would be delegated
			for _, rr := range n.RRs {
				if _, ok := rr.(*dns.NS); ok {
					delegated[n.Name] = struct{}{}
					break
				}
			}
		}
		auth, end := true, false
		i, j := 0, 0
		for ; !end; j, end = dnsutil.Next(n.Name, i) {
			if len(n.Name[j:]) < len(z.Origin()) {
				break
			}
			if _, ok := delegated[n.Name[j:]]; ok {
				// If we have zone cut records, which is NSEC, DS and DELEG, this is authoritative data.
				// This must be signed, but NOT the NSs in there.
				auth = false
				if zonecut(n) {
					auth = true
				}

				break
			}
			i++
		}

		return fn(n, auth)
	})
}

// zonecut returns true if all RR in n are needed for a zone cut. That is: is there authoritative data in this
// zonecut that we still have to sign like DS, NSEC.
func zonecut(n *dnszone.Node) bool {
	i := 0
	for _, rr := range n.RRs {
		switch t := dns.RRToType(rr); t {
		case dns.TypeNS:
			i++
		case dns.TypeDS:
			i++
		case dns.TypeDELEG:
			i++
		case dns.TypeNSEC, dns.TypeNSEC3:
			i++
		}
	}
	return i == len(n.RRs)
}
