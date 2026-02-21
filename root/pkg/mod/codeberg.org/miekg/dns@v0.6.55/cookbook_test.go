package dns_test

// This files has (testable) snippets to document  how to do common tasks.
// Feel free to add ones you encountered when using this library.

import (
	"fmt"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// ExampleHeader_replace shows how to overwrite a header.
func ExampleHeader_replace() {
	rr := &dns.MX{}
	*(rr.Header()) = dns.Header{Name: dnsutil.Fqdn("example.org"), Class: dns.ClassINET}
	// Or
	hdr := rr.Header()
	*hdr = dns.Header{Name: dnsutil.Fqdn("example.org"), Class: dns.ClassINET}
	// Or
	rr.Header().Name = "example.org."
	rr.Header().Class = dns.ClassINET
}

// ExampleRDATA shows how to access the various elements in a [dns.RR].
func ExampleRDATA() {
	rr := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
	rh := rr.Header()
	rd := rr.Data()
	fmt.Println("Split RR")
	fmt.Printf("Record = %v\n", rr)
	fmt.Printf("Header = %v\n", rh)
	fmt.Printf("Data   = %v\n", rd)

	// Updating rr.Preference does not affect rd, rd is a copy.
	rr.Preference = 20
	fmt.Printf("Data   = %v\n", rd) // Still 10 mx.miek.nl.

	// Updating rd.Preference does not affect rr.
	rdmx := rd.(rdata.MX) // Need this otherwise:  cannot assign to rd.(rdata.MX).Preference (neither addressable nor a map index expression)
	rdmx.Preference = 20

	// Update the RR with the new rdata.
	fn := dns.TypeToRDATA[dns.TypeMX]
	fn(rr, rdmx)
	fmt.Printf("Record = %v\n", rr) // .... 20 mx.miek.nl.
}
