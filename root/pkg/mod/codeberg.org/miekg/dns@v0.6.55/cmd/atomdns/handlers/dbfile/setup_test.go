package dbfile

import (
	"slices"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Dbfile
	}{
		{`dbfile db.example`, &Dbfile{Path: "db.example"}},
		{
			`dbfile db.example {
			transfer {
				to {
					notify 10.240.1.1
        			}
			}
		}`,
			&Dbfile{Path: "db.example", To: &Transfer{IPs: []string{}, Notifies: []string{"10.240.1.1:53"}}},
		},
		{
			`dbfile db.example {
			transfer {
				to 172.16.16.1 {
					notify 10.240.1.1
        			}
			}
		}`,
			&Dbfile{Path: "db.example", To: &Transfer{IPs: []string{"172.16.16.1:53"}, Notifies: []string{"10.240.1.1:53"}}},
		},
		{
			`dbfile db.example {
			transfer {
				to 172.16.16.1 {
					notify 10.240.1.1
            				key miek.nl hmac-sha224 aGFsbG8K
					source 10.10.10.10
        			}
				from 244.22.21.10
			}
		}`,
			&Dbfile{
				Path: "db.example",
				To: &Transfer{
					IPs:        []string{"172.16.16.1:53"},
					Sources:    []string{"10.10.10.10"},
					Notifies:   []string{"10.240.1.1:53"},
					TSIGSecret: "aGFsbG8K",
				},
				From: &Transfer{
					IPs: []string{"244.22.21.10:53"},
				},
			},
		},
	}
	for i, tc := range testcases {
		dbfile := new(Dbfile)
		co := dnsserver.NewTestController(tc.input)
		err := dbfile.Setup(co)
		if err != nil {
			t.Fatal(err)
		}

		if tc.exp.Path != dbfile.Path {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Path, dbfile.Path)
		}
		if tc.exp.To != nil {
			if slices.Compare(tc.exp.To.IPs, dbfile.To.IPs) != 0 {
				t.Errorf("test %d: expected %v, got %v", i, tc.exp.To.IPs, dbfile.To.IPs)
			}
			if slices.Compare(tc.exp.To.Notifies, dbfile.To.Notifies) != 0 {
				t.Errorf("test %d: expected %v, got %v", i, tc.exp.To.Notifies, dbfile.To.Notifies)
			}
			if slices.Compare(tc.exp.To.Sources, dbfile.To.Sources) != 0 {
				t.Errorf("test %d: expected %v, got %v", i, tc.exp.To.Sources, dbfile.To.Sources)
			}
			if tc.exp.To.TSIGSecret != dbfile.To.TSIGSecret {
				t.Errorf("test %d: expected %s, got %s", i, tc.exp.To.TSIGSecret, dbfile.To.TSIGSecret)
			}
		}
		if tc.exp.From != nil {
			if slices.Compare(tc.exp.From.IPs, dbfile.From.IPs) != 0 {
				t.Errorf("test %d: expected %v, got %v", i, tc.exp.From.IPs, dbfile.From.IPs)
			}
			if tc.exp.From.TSIGSecret != dbfile.From.TSIGSecret {
				t.Errorf("test %d: expected %s, got %s", i, tc.exp.From.TSIGSecret, dbfile.From.TSIGSecret)
			}
		}
	}
}
