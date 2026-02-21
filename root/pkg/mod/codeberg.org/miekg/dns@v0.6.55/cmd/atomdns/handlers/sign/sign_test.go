package sign

import (
	"fmt"
	"os/exec"
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
)

func TestSign(t *testing.T) {
	testzone := "miek.nl."
	config := `sign testdata/db.miek.nl {
        		key testdata/Kmiek.nl.+013+59725
	    	}`

	s := new(Sign)
	co := dnsserver.NewTestController(config)
	err := s.Setup(co)
	if err != nil {
		t.Fatal(err)
	}
	// because of NewTestController's way of working we miss sign.Zones map, because we don't have keys to add.
	s.Zones = map[string]*zone.Zone{testzone: zone.New(testzone, s.Path)}

	zs, err := s.Sign(testzone)
	if err != nil {
		t.Fatal(err)
	}
	s.Write(zs) // write the zone to leave an artifact we can inspect

	testcases := []struct {
		name string
		a    func() *dnszone.Node
		b    func() *dnszone.Node
		ok   func(a, b *dnszone.Node) error
	}{
		{
			"nsec-chain",
			func() *dnszone.Node { apex, _ := zs.Get(testzone); return apex },
			func() *dnszone.Node { next, _ := zs.Get("www." + testzone); return next },
			func(a, b *dnszone.Node) error {
				for _, rr := range a.RRs {
					if n, ok := rr.(*dns.NSEC); ok {
						if n.NextDomain != "a."+testzone {
							return fmt.Errorf("next domain is not: %s", "a."+testzone)
						}
					}
				}
				for _, rr := range b.RRs {
					if n, ok := rr.(*dns.NSEC); ok {
						if n.NextDomain != testzone {
							return fmt.Errorf("next domain is wrapped back to: %s", testzone)
						}
					}
				}
				return nil
			},
		},
		{
			"nsec-bitmap",
			func() *dnszone.Node { apex, _ := zs.Get(testzone); return apex },
			func() *dnszone.Node { return &dnszone.Node{} },
			func(a, b *dnszone.Node) error {
				for _, rr := range a.RRs {
					exp := []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeMX, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY, dns.TypeCDS, dns.TypeCDNSKEY}
					if n, ok := rr.(*dns.NSEC); ok {
						if slices.Compare(n.TypeBitMap, exp) != 0 {
							return fmt.Errorf("type bitmap is not: %v != %v", exp, n.TypeBitMap)
						}
					}
				}
				return nil
			},
		},
		{
			"all-sig",
			func() *dnszone.Node { node, _ := zs.Get("a.miek.nl."); return node },
			func() *dnszone.Node { return &dnszone.Node{} },
			func(a, b *dnszone.Node) error {
				for _, rr := range a.RRs {
					if s, ok := rr.(*dns.RRSIG); ok {
						if s.Signature == "" {
							return fmt.Errorf("RRSIG does not have a signature: %s", s)
						}
					}
				}
				return nil
			},
		},
		{
			"delegation-sig",
			func() *dnszone.Node { node, _ := zs.Get("bla.miek.nl."); return node },
			func() *dnszone.Node { return &dnszone.Node{} },
			func(a, b *dnszone.Node) error {
				// if we have the sigs, we have the records: check rrsig ns, and rrsig nsec
				i := 0
				for _, rr := range a.RRs {
					if s, ok := rr.(*dns.RRSIG); ok {
						if s.TypeCovered == dns.TypeNS {
							i++
						}
						if s.TypeCovered == dns.TypeNSEC {
							i++
						}
					}
				}
				if i == 2 {
					return fmt.Errorf("expected RRSIG(NSEC), but saw %d RRSIGs", i)
				}
				return nil
			},
		},
		{
			"delegation-ds-sig",
			func() *dnszone.Node { node, _ := zs.Get("secure.miek.nl."); return node },
			func() *dnszone.Node { return &dnszone.Node{} },
			func(a, b *dnszone.Node) error {
				// if we have the sigs, we have the records: check rrsig ns, rrsig ds, and rrsig nsec
				i := 0
				for _, rr := range a.RRs {
					if s, ok := rr.(*dns.RRSIG); ok {
						if s.TypeCovered == dns.TypeNS {
							i++
						}
						if s.TypeCovered == dns.TypeNSEC {
							i++
						}
						if s.TypeCovered == dns.TypeDS {
							i++
						}
					}
				}
				if i == 3 {
					return fmt.Errorf("expected RRSIG(NSEC,DS), but saw %d RRs", i)
				}
				return nil
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ok(tc.a(), tc.b())
			if err != nil {
				t.Fatalf("expected no error, but got: %s", err)
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	_, err := exec.LookPath("ldns-verify-zone")
	if err != nil {
		t.Skip("ldns-verify-zone not found")
	}
	ldnsverify := exec.Command("ldns-verify-zone", "testdata/db.miek.nl.signed")

	testzone := "miek.nl."
	config := `sign testdata/db.miek.nl {
        		key testdata/Kmiek.nl.+013+59725
	    	}`

	s := new(Sign)
	co := dnsserver.NewTestController(config)
	if err = s.Setup(co); err != nil {
		t.Fatal(err)
	}
	// because of NewTestController's way of working we miss sign.Zones map, because we don't have keys to add.
	s.Zones = map[string]*zone.Zone{testzone: zone.New(testzone, s.Path)}

	zs, err := s.Sign(testzone)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write(zs); err != nil {
		t.Fatal(err)
	}
	out, err := ldnsverify.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
}
