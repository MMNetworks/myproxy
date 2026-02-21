package deleg_test

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
)

func TestDELEG(t *testing.T) {
	// TODO(miek): include more tests, or rename the test.
	testcases := []struct {
		in  string
		exp dns.RR
	}{
		{
			"$ORIGIN example.\nexample.   DELEG server-ipv4=192.0.2.1 server-ipv6=2001:DB8::1\n",
			dnstest.New("example. IN 3600  DELEG server-ipv4=192.0.2.1 server-ipv6=2001:DB8::1"),
		},
		{
			"$ORIGIN example.\nexample.   DELEG server-name=ns2,ns3.example.org.\n",
			dnstest.New("example. IN 3600  DELEG server-name=ns2.example.,ns3.example.org."),
		},
		{
			"example.   DELEG\n",
			dnstest.New("example. IN 3600  DELEG"),
		},
	}
	for i, tc := range testcases {
		rr, err := dns.New(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s\n", rr)
		if !dns.Equal(rr, tc.exp) {
			t.Errorf("test %d, expected %s, got %s", i, rr, tc.exp)
		}
	}
}
