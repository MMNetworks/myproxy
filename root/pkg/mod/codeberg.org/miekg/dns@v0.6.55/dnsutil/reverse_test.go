package dnsutil

import (
	"net/netip"
	"testing"
)

func TestAddrReverse(t *testing.T) {
	testcases := []struct {
		reverse string
		addr    netip.Addr
	}{
		{"54.119.58.176.in-addr.arpa.", netip.MustParseAddr("176.58.119.54")},
		{".58.176.in-addr.arpa.", netip.Addr{}},
		{"b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.in-addr.arpa.", netip.Addr{}},
		{"b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", netip.MustParseAddr("2001:db8::567:89ab")},
		{"d.0.1.0.0.2.ip6.arpa.", netip.Addr{}},
		{"54.119.58.176.ip6.arpa.", netip.Addr{}},
		{"NONAME", netip.Addr{}},
		{"", netip.Addr{}},
	}
	for i, tc := range testcases {
		got := AddrReverse(tc.reverse)
		if got != tc.addr {
			t.Errorf("Test %d, expected '%s', got '%s'", i, tc.addr, got)
		}
	}
}

func BenchmarkAddrReverse(b *testing.B) {
	b.Run("IPv4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			AddrReverse("54.119.58.176.in-addr.arpa.")
		}
	})
	b.Run("IPv6", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			AddrReverse("b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.")
		}
	})
}
