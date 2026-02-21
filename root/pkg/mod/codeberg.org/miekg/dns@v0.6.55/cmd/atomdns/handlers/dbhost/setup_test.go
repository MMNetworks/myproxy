package dbhost

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Dbhost
	}{
		{`dbhost`, &Dbhost{Path: "/etc/hosts", ttl: 3600}},
		{`dbhost /dev/null`,
			&Dbhost{Path: "/dev/null", ttl: 3600}},
		{`dbhost {
			ttl 5
		}`,
			&Dbhost{Path: "/etc/hosts", ttl: 5}},
		{`dbhost /dev/null {
			ttl 5
		}`,
			&Dbhost{Path: "/dev/null", ttl: 5}},
	}

	for i, tc := range testcases {
		dbhost := new(Dbhost)
		co := dnsserver.NewTestController(tc.input)
		err := dbhost.Setup(co)
		if err != nil {
			t.Fatalf("test %d: %s", i, err)
		}

		if tc.exp.Path != dbhost.Path {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Path, dbhost.Path)
		}
		if tc.exp.ttl != dbhost.ttl {
			t.Errorf("test %d: expected %d, got %d", i, tc.exp.ttl, dbhost.ttl)
		}
	}
}
