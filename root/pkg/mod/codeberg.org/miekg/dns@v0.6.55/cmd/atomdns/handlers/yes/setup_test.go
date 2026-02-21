package yes

import (
	"slices"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Yes
	}{
		{
			`yes {
				caa aaa
				caa bb
				ns ns2.example.org
			}
		}`,
			&Yes{Caa: []string{"aaa", "bb"}, Ns: "ns2.example.org."},
		},
		{
			`yes {
				caa aaa
				ns ns1.example.org
			}
		}`,
			&Yes{Caa: []string{"aaa"}, Ns: "ns1.example.org."},
		},
	}
	for i, tc := range testcases {
		yes := new(Yes)
		co := dnsserver.NewTestController(tc.input)
		err := yes.Setup(co)
		if err != nil {
			t.Error(err)
			continue
		}

		if slices.Compare(tc.exp.Caa, yes.Caa) != 0 {
			t.Errorf("test %d: expected %v, got %v", i, tc.exp.Caa, yes.Caa)
		}
		if tc.exp.Ns != yes.Ns {
			t.Errorf("test %d: expected %q, got %q", i, tc.exp.Ns, yes.Ns)
		}
	}
}
