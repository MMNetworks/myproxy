package dnsutil

import (
	"fmt"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestToString(t *testing.T) {
	if x := RcodeToString(5); x != "REFUSED" {
		t.Errorf("expected %s, got %s", "REFUSED", x)
	}
	if x := RcodeToString(55); x != "RCODE55" {
		t.Errorf("expected %s, got %s", "RCODE55", x)
	}
	if x := OpcodeToString(0); x != "QUERY" {
		t.Errorf("expected %s, got %s", "QUERY", x)
	}
	if x := OpcodeToString(12); x != "OPCODE12" {
		t.Errorf("expected %s, got %s", "OPCODE12", x)
	}
	if x := TypeToString(1); x != "A" {
		t.Errorf("expected %s, got %s", "A", x)
	}
	if x := ClassToString(1); x != "IN" {
		t.Errorf("expected %s, got %s", "IN", x)
	}
}

func ExampleTypeToString() {
	rr := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
	fmt.Println(TypeToString(dns.RRToType(rr)))
	// Output: MX
}
