package localaddr

import (
	"net"
	"testing"

	"codeberg.org/miekg/dns/dnsutil"
)

func TestSource(t *testing.T) {
	testcases := []struct {
		sources []string
		fam     int
		exp     net.IP
	}{
		{[]string{"127.0.0.1"}, dnsutil.IPv6Family, nil},
		{[]string{"127.0.0.1"}, dnsutil.IPv4Family, net.ParseIP("127.0.0.1").To4()},
		{[]string{"127.0.0.1", "::1"}, dnsutil.IPv4Family, net.ParseIP("127.0.0.1").To4()},
		{[]string{"127.0.0.1", "::1"}, dnsutil.IPv6Family, net.ParseIP("::1")},
		{[]string{"127.0.0.1:53", "[::1]:53"}, dnsutil.IPv6Family, net.ParseIP("::1")},
		{[]string{"::1"}, dnsutil.IPv4Family, nil},
		{[]string{}, dnsutil.IPv4Family, nil},
	}
	for i, tc := range testcases {
		got := Source(tc.fam, tc.sources)
		if !tc.exp.Equal(got) {
			t.Errorf("test %d, expected %q, got %q", i, tc.exp, got)

		}
	}
}
