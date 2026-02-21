package dns_test

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// Example on how get the text presentation of a [dns.RR].
func ExampleRDATA_string() {
	rr := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
	s := rr.Header().String() + " " + dnsutil.TypeToString(dns.RRToType(rr)) + "\t" + rr.Data().String()
	fmt.Println(s)
	// Output: miek.nl.	3600	IN MX	10 mx.miek.nl.
}

// Example on how to set the rdata of an RR.
func ExampleRDATA_newData() {
	rd, _ := dns.NewData(dns.TypeMX, "10 mx.miek.nl.")
	rr := dns.TypeToRR[dns.TypeMX]()
	rr.Header().Name = "miek.nl."
	rr.Header().Class = dns.ClassINET
	fn := dns.TypeToRDATA[dns.TypeMX]
	// Set the rdata in the rr.
	fn(rr, rd)
	fmt.Println(rr)
	// Output: miek.nl.	0	IN	MX	10 mx.miek.nl.
}

func TestTypeToRDATA(t *testing.T) {
	testcases := []struct {
		name string
		t    uint16
		in   string
		fn   func(rr dns.RR) error
	}{
		{
			"mx",
			dns.TypeMX,
			"10 mx.miek.nl.",
			func(rr dns.RR) error {
				mx, ok := rr.(*dns.MX)
				if !ok {
					return fmt.Errorf("expected MX, got %T", rr)
				}
				if mx.Preference != 10 {
					return fmt.Errorf("expected 10, got %d", mx.Preference)
				}
				if mx.Mx != "mx.miek.nl." {
					return fmt.Errorf("expected mx.miek.nl., got %s", mx.Mx)
				}
				return nil
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			rd, _ := dns.NewData(tc.t, tc.in, ".")
			rr := dns.TypeToRR[tc.t]()
			fn := dns.TypeToRDATA[tc.t]
			fn(rr, rd)

		})
	}
}

func TestNewData(t *testing.T) {
	testcases := []struct {
		name string
		t    uint16
		in   string
		fn   func(rd dns.RDATA) error
	}{
		{
			"mx-origin-ok",
			dns.TypeMX,
			"10 mx.miek.nl",
			func(rd dns.RDATA) error {
				if rd == nil {
					return fmt.Errorf("expected rd, got none")
				}
				mx := rd.(rdata.MX)
				if mx.Preference != 10 {
					return fmt.Errorf("expected 10, got %d", mx.Preference)
				}
				if mx.Mx != "mx.miek.nl." {
					return fmt.Errorf("expected mx.miek.nl., got %s", mx.Mx)
				}
				return nil
			},
		},
		{
			"mx-ok",
			dns.TypeMX,
			"10 mx.miek.nl.",
			func(rd dns.RDATA) error {
				if rd == nil {
					return fmt.Errorf("expected rd, got none")
				}
				mx := rd.(rdata.MX)
				if mx.Preference != 10 {
					return fmt.Errorf("expected 10, got %d", mx.Preference)
				}
				if mx.Mx != "mx.miek.nl." {
					return fmt.Errorf("expected mx.miek.nl., got %s", mx.Mx)
				}
				return nil
			},
		},
		{
			"mx-space-fail",
			dns.TypeMX,
			" 10 mx.miek.nl.",
			func(rd dns.RDATA) error {
				if rd.(rdata.MX).Preference == 0 {
					return nil
				}
				return fmt.Errorf("expected nil rd: %v", rd)
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			rd, _ := dns.NewData(tc.t, tc.in, ".")
			if err := tc.fn(rd); err != nil {
				t.Fatal(err)
			}
		})
	}
}
