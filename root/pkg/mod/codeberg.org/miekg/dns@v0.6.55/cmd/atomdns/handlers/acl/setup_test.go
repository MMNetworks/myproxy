package acl

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		name   string
		config string
		exp    bool
	}{
		{
			"blocklist",
			`acl {
				block A 192.168.0.0/16
			}`,
			false,
		},
		{
			"blocklist",
			`acl {
				block 192.168.0.0/16
			}`,
			false,
		},
		{
			"blocklist",
			`acl {
				block A
			}`,
			false,
		},
		{
			"blocklist",
			`acl {
				allow 192.168.1.0/24
				block 192.168.0.0/16
			}`,
			false,
		},
		{
			"filter",
			`acl {
				filter A 192.168.0.0/16
			}`,
			false,
		},
		{
			"allowlist",
			`acl {
				allow 192.168.0.0/16
				block
			}`,
			false,
		},
		{
			"drop",
			`acl {
				drop 192.168.0.0/16
			}`,
			false,
		},
		{
			"multiple networks",
			`acl {
				block 192.168.1.0/24 192.168.3.0/24
			}`,
			false,
		},
		{
			"multiple qtypes",
			`acl {
				block TXT ANY CNAME 192.168.3.0/24
			}`,
			false,
		},
		{
			"illegal argument",
			`acl {
				block ABC 192.168.0.0/16
			}`,
			true,
		},
		{
			"illegal argument",
			`acl {
				blck A 192.168.0.0/16
			}`,
			true,
		},
		{
			"blocklist IPv6",
			`acl {
				block A 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			}`,
			false,
		},
		{
			"blocklist IPv6",
			`acl {
				allow 2001:db8:abcd:0012::0/64
				block 2001:db8:abcd:0012::0/48
			}`,
			false,
		},
		{
			"filter IPv6",
			`acl {
				filter A 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			}`,
			false,
		},
		{
			"fine-grained IPv6",
			`acl {
				block 2001:db8:abcd:0012::0/64
			}`,
			false,
		},
		{
			"multiple networks IPv6",
			`acl {
				block 2001:db8:abcd:0012::0/64 2001:db8:85a3::8a2e:370:7334/64
			}`,
			false,
		},
		{
			"illegal argument IPv6",
			`acl {
				block A 2001::85a3::8a2e:370:7334
			}`,
			true,
		},
		{
			"illegal argument IPv6",
			`acl {
				block A 2001:db8:85a3:::8a2e:370:7334
			}`,
			true,
		},
		{
			"switch rule types",
			`acl {
				block A Cambridge
			}`,
			true,
		},
		{
			"switch rule types",
			`acl {
				block 192.168.0.0/16 Cambridge
			}`,
			true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			acl := new(Acl)
			co := dnsserver.NewTestController(tc.config)
			err := acl.Setup(co)
			if (err != nil) != tc.exp {
				t.Errorf("expected %t, for %s", tc.exp, tc.config)
			}
		})
	}
}
