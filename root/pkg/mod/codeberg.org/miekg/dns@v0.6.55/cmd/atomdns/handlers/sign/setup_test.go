package sign

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Sign
	}{
		{`sign db.example.org {
        		key testdata/Kmiek.nl.+013+59725
			}`, &Sign{Path: "db.example.org", Directory: "."}},
		{`sign db.example.org {
        		key testdata/Kmiek.nl.+013+59725
			directory /tmp
			}`, &Sign{Path: "db.example.org", Directory: "/tmp"}},
	}

	for i, tc := range testcases {
		sign := new(Sign)
		co := dnsserver.NewTestController(tc.input)
		err := sign.Setup(co)
		if err != nil {
			t.Fatal(err)
		}

		if tc.exp.Path != sign.Path {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Path, sign.Path)
		}
		if tc.exp.Directory != sign.Directory {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Directory, sign.Directory)
		}
	}
}
