package dnsreverse

import (
	"math"
	"net"
	"net/netip"
	"strings"

	"codeberg.org/miekg/dns/dnsutil"
	"github.com/apparentlymart/go-cidr/cidr"
)

// Zones return the reverse zones that are authoritative for each net in n.
func Zones(n *net.IPNet) []string {
	nets := split(n)
	rev := make([]string, len(nets))
	for i := range nets {
		ip, n, _ := net.ParseCIDR(nets[i])

		addr, _ := netip.AddrFromSlice(ip)
		r := dnsutil.ReverseAddr(addr)
		if len(n.IP) != net.IPv6len {
			addr, _ := netip.AddrFromSlice(ip.To4())
			r = dnsutil.ReverseAddr(addr)
		}
		if r == "" {
			continue
		}

		ones, bits := n.Mask.Size()
		// get the size, in bits, of each portion of hostname defined in the reverse address. (8 for IPv4, 4 for IPv6)
		sizeDigit := 8
		if len(n.IP) == net.IPv6len {
			sizeDigit = 4
		}
		// Get the first lower octet boundary to see what encompassing zone we should be authoritative for.
		mod := (bits - ones) % sizeDigit
		nearest := (bits - ones) + mod
		offset := 0
		var end bool
		for i := 0; i < nearest/sizeDigit; i++ {
			offset, end = dnsutil.Next(r, offset)
			if end {
				break
			}
		}
		rev[i] = r[offset:]
	}
	return rev
}

// split returns a slice of non-overlapping subnets that in union equal the subnet n,
// and where each subnet falls on a reverse name segment boundary.
// For ipv4 this is any multiple of 8 bits (/8, /16, /24 or /32).
// For ipv6 this is any multiple of 4 bits.
func split(n *net.IPNet) []string {
	boundary := 8
	nstr := n.String()
	if strings.Contains(nstr, ":") {
		boundary = 4
	}
	ones, _ := n.Mask.Size()
	if ones%boundary == 0 {
		return []string{n.String()}
	}

	mask := int(math.Ceil(float64(ones)/float64(boundary))) * boundary
	networks := nets(n, mask)
	cidrs := make([]string, len(networks))
	for i := range networks {
		cidrs[i] = networks[i].String()
	}
	return cidrs
}

// nets return a slice of prefixes with the desired mask subnetted from original network.
func nets(network *net.IPNet, newPrefixLen int) []*net.IPNet {
	prefixLen, _ := network.Mask.Size()
	max := int(math.Exp2(float64(newPrefixLen)) / math.Exp2(float64(prefixLen)))
	nets := []*net.IPNet{{IP: network.IP, Mask: net.CIDRMask(newPrefixLen, 8*len(network.IP))}}

	for i := 1; i < max; i++ {
		next, exceeds := cidr.NextSubnet(nets[len(nets)-1], newPrefixLen)
		nets = append(nets, next)
		if exceeds {
			break
		}
	}

	return nets
}
