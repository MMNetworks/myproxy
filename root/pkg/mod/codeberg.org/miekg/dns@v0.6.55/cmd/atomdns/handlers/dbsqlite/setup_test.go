package dbsqlite

import (
	"slices"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Dbsqlite
	}{
		{`dbsqlite db.example`, &Dbsqlite{Path: "db.example"}},
		{
			`dbsqlite db.example {
                        transfer {
                                to {
                                        notify 10.240.1.1
                                }
                        }
                }`,
			&Dbsqlite{Path: "db.example", To: &dbfile.Transfer{IPs: []string{}, Notifies: []string{"10.240.1.1:53"}}},
		},
		{
			`dbsqlite db.example {
                        transfer {
                                to 172.16.16.1 {
                                        notify 10.240.1.1
                                }
                        }
                }`,
			&Dbsqlite{Path: "db.example", To: &dbfile.Transfer{IPs: []string{"172.16.16.1:53"}, Notifies: []string{"10.240.1.1:53"}}},
		},
		{
			`dbsqlite db.example {
                        transfer {
                                to 172.16.16.1 {
                                        notify 10.240.1.1
                                        key miek.nl hmac-sha224 aGFsbG8K
                                        source 10.10.10.10
                                }
                        }
                }`,
			&Dbsqlite{
				Path: "db.example",
				To: &dbfile.Transfer{
					IPs:        []string{"172.16.16.1:53"},
					Sources:    []string{"10.10.10.10:53"},
					Notifies:   []string{"10.240.1.1:53"},
					TSIGSecret: "aGFsbG8K",
				},
			},
		},
	}
	for i, tc := range testcases {
		dbsqlite := new(Dbsqlite)
		co := dnsserver.NewTestController(tc.input)
		err := dbsqlite.Setup(co)
		if err != nil {
			t.Fatal(err)
		}

		if tc.exp.Path != dbsqlite.Path {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Path, dbsqlite.Path)
		}
		if tc.exp.To != nil {
			if slices.Compare(tc.exp.To.IPs, dbsqlite.To.IPs) != 0 {
				t.Errorf("test %d: expected %v, got %v", i, tc.exp.To.IPs, dbsqlite.To.IPs)
			}
			if slices.Compare(tc.exp.To.Notifies, dbsqlite.To.Notifies) != 0 {
				t.Errorf("test %d: expected %v, got %v", i, tc.exp.To.Notifies, dbsqlite.To.Notifies)
			}
			if slices.Compare(tc.exp.To.Sources, dbsqlite.To.Sources) != 0 {
				t.Errorf("test %d: expected %v, got %v", i, tc.exp.To.Sources, dbsqlite.To.Sources)
			}
			if tc.exp.To.TSIGSecret != dbsqlite.To.TSIGSecret {
				t.Errorf("test %d: expected %s, got %s", i, tc.exp.To.TSIGSecret, dbsqlite.To.TSIGSecret)
			}
		}
	}
}
