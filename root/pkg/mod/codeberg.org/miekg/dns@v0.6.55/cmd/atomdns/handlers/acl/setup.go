package acl

import (
	"net/netip"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"github.com/phemmer/go-iptrie"
)

const (
	nettype = iota
	contextype
)

func (a *Acl) Setup(co *dnsserver.Controller) error {
	var IPv4All, _ = netip.ParsePrefix("0.0.0.0/0")
	var IPv6All, _ = netip.ParsePrefix("::/0")

	a.N = co.Global.MetricsN

	for co.Next() {
		r := rule{}
		for co.NextBlock(0) {
			p := policy{}

			switch co.Val() {
			case "allow":
				p.action = dns.MsgAccept
			case "block":
				p.action = dns.MsgReject
			case "filter":
				p.action = MsgFilter
			case "drop":
				p.action = dns.MsgIgnore
			default:
				return co.Errf("unexpected token %q, expected 'allow', 'block', 'filter' or 'drop'", co.Val())
			}

			args := co.RemainingArgs()

			if len(args) == 0 {
				p.net = &policyNet{filter: iptrie.NewTrie()}
				p.net.filter.Insert(IPv4All, nil)
				p.net.filter.Insert(IPv6All, nil)
				r.policies = append(r.policies, p)
				continue
			}

			hasnet := false
			// qtype, cidr of ctx key
			tp := contextype
			if dns.StringToType[args[0]] != 0 {
				tp = nettype
			}
			if _, err := netip.ParsePrefix(normalize(args[0])); err == nil { // == nil
				tp = nettype
			}
			if tp == contextype && !dnsctx.Valid(args[0]) {
				return co.Errf("invalid context key: %s", args[0])
			}
			if tp == nettype {
				p.net = &policyNet{filter: iptrie.NewTrie()}
			}
			for i, arg := range args {
				switch tp {
				case contextype:
					if i == 0 {
						p.ctx = new(policyCtx)
						p.ctx.ctx = arg
					} else {
						p.ctx.values = append(p.ctx.values, argtotype(arg))
					}
				case nettype:
					qtype := dns.StringToType[arg]
					if qtype != 0 {
						p.net.qtypes = append(p.net.qtypes, qtype)
					} else {
						source, err := netip.ParsePrefix(normalize(arg))
						if err != nil {
							return co.Errf("illegal CIDR notation %q", normalize(arg))
						}
						hasnet = true
						p.net.filter.Insert(source, nil)
					}
				}
			}
			if tp == nettype && !hasnet {
				p.net.filter.Insert(IPv4All, nil)
				p.net.filter.Insert(IPv6All, nil)
				hasnet = true
			}
			r.policies = append(r.policies, p)
		}
		a.Rules = append(a.Rules, r)
	}
	return nil
}

// normalize appends '/32' for any single IPv4 address and '/128' for IPv6.
func normalize(rawNet string) string {
	if strings.Contains(rawNet, "/") {
		return rawNet
	}
	if strings.Contains(rawNet, ":") {
		return rawNet + "/128"
	}
	return rawNet + "/32"
}

// argtotype take the string arg and determines what the type could be and returns it. I.e. "true" will be
// parsed as a bool that is true. This functions handles strings, int, float64s and bools.
func argtotype(arg string) any {
	if arg == "true" {
		return true
	}
	if arg == "false" {
		return false
	}
	if i, err := strconv.ParseInt(arg, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(arg, 64); err == nil {
		return f
	}
	return arg
}
