package acl_test

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/atomtest"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/acl"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

var testcases = []struct {
	name   string
	config string
	qtype  uint16
	setup  func() context.Context

	rcode         int
	extendedError uint16
	noResponse    bool
}{
	{
		name: "block all",
		config: `acl {
				block
			}`,
		rcode: dns.RcodeRefused,
	},
	{
		name: "blocklist block",
		config: `acl {
				block A 198.51.100.0/16
			}`,
		rcode:         dns.RcodeRefused,
		extendedError: dns.ExtendedErrorBlocked,
	},
	{
		name: "blocklist allowed",
		config: `acl {
				block A 192.168.0.0/16
			}`,
	},
	{
		name: "blocklist all blocked",
		config: `acl {
				block 198.51.100.0/16
			}`,
		qtype:         dns.TypeAAAA,
		rcode:         dns.RcodeRefused,
		extendedError: dns.ExtendedErrorBlocked,
	},
	{
		name: "block A and allow AAAA",
		config: `acl {
				block A 198.51.100.0/16
				allow AAAA 198.51.100.0/16
				allow TXT
			}`,
		rcode:         dns.RcodeRefused,
		extendedError: dns.ExtendedErrorBlocked,
	},
	{
		name: "block A and allow AAAA",
		config: `acl {
				block A 198.51.100.0/16
				allow AAAA 198.51.100.0/16
				allow TXT
			}`,
		qtype: dns.TypeAAAA,
	},
	{
		name: "block A, not TXT",
		config: `acl {
				block A
				allow TXT
			}`,
		rcode:         dns.RcodeRefused,
		extendedError: dns.ExtendedErrorBlocked,
	},
	{
		name: "block A, not TXT",
		config: `acl {
				block A
				allow TXT
			}`,
		qtype: dns.TypeTXT,
	},
	{
		name:  "ctx: block Cambridge",
		setup: func() context.Context { return context.WithValue(context.TODO(), "geoip/city", "Cambridge") },
		config: `acl {
				block geoip/city Cambridge
			}`,
		rcode: dns.RcodeRefused,
	},
	{
		name: "ctx: block Cambridge",
		setup: func() context.Context {
			return context.WithValue(context.WithValue(context.TODO(), "geoip/country/eu", true), "geoip/city", "Amsterdam")
		},
		config: `acl {
				block geoip/city Cambridge
				allow geoip/country/eu true
			}`,
	},
}

func TestAcl(t *testing.T) {
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			a := new(acl.Acl)
			co := dnsserver.NewTestController(tc.config)
			a.Setup(co)

			tw := dnstest.NewTestRecorder()
			m := new(dns.Msg)
			if tc.qtype == 0 {
				tc.qtype = dns.TypeA
			}
			dnsutil.SetQuestion(m, "www.example.org.", tc.qtype)

			ctx := context.TODO()
			if tc.setup != nil {
				ctx = tc.setup()
			}
			a.HandlerFunc(atomtest.Echo).ServeDNS(ctx, tw, m)

			tw.Msg.Unpack()
			if tw.Msg.Rcode != uint16(tc.rcode) {
				t.Errorf("rcode mismatch want %d, got %d", tc.rcode, tw.Msg.Rcode)
			}
			if tc.noResponse && tw.Msg != nil {
				t.Errorf("responded to client when not expected")
			}
			if tc.extendedError != 0 {
				for _, p := range tw.Msg.Pseudo {
					if ede, ok := p.(*dns.EDE); ok {
						if ede.InfoCode != tc.extendedError {
							t.Errorf("expected extended error %d, got %d", ede.InfoCode, tc.extendedError)
						}
					}
				}
			}
		})
	}
}
