package acl

import (
	"context"
	"net/netip"
	"slices"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/phemmer/go-iptrie"
)

// rule defines ACL policies which will be enforced.
type rule struct {
	policies []policy
}

// policy defines the ACL policy for DNS messages.
// A policy performs the specified action (block/allow) on all DNS messages matched by source IP or QTYPE.
type policy struct {
	action dns.MsgAcceptAction

	// One of these is non-nil and carries the policy
	net *policyNet
	ctx *policyCtx
}

type policyNet struct {
	qtypes []uint16
	filter *iptrie.Trie
}

type policyCtx struct {
	ctx    string
	values []any
}

const MsgFilter = dns.MsgAcceptAction(10)

// match matches the DNS message with a list of ACL polices and returns suitable action against the message.
func match(ctx context.Context, policies []policy, w dns.ResponseWriter, r *dns.Msg) dns.MsgAcceptAction {
	for _, policy := range policies {
		switch {
		case policy.net != nil:
			ip := netip.MustParseAddr(dnsutil.RemoteIP(w))
			if x := dnsctx.Addr(ctx, "etc/address"); x.IsValid() {
				ip = x
			}

			_, qtype := dnsutil.Question(r)
			matchAll := len(policy.net.qtypes) == 0
			match := slices.Contains(policy.net.qtypes, qtype)
			if !matchAll && !match {
				continue
			}

			if !policy.net.filter.Contains(ip) {
				continue
			}
			return policy.action
		case policy.ctx != nil:
			if dnsctx.Match(ctx, policy.ctx.ctx, policy.ctx.values) {
				return policy.action
			}
		}
	}
	return dns.MsgAccept
}
