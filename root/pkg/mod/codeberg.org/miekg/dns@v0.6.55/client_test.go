package dns_test

import (
	"context"
	"fmt"
	"log"

	"codeberg.org/miekg/dns"
)

func ExampleClient_Exchange() {
	m := dns.NewMsg("www.example.org", dns.TypeA)
	r, err := dns.Exchange(context.TODO(), m, "udp", "8.8.8.8:53")
	if err != nil {
		log.Printf("Failed to exchange: %v", err)
		return
	}
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			fmt.Println(a.A)
		}
	}
}

func ExampleClient_Exchange_nxdomain() {
	m := dns.NewMsg("wwww.example.org", dns.TypeA)
	r, err := dns.Exchange(context.TODO(), m, "udp", "8.8.8.8:53")
	if err != nil {
		log.Printf("Failed to exchange: %v", err)
		return
	}
	if m.Rcode != dns.RcodeNameError {
		log.Printf("Expected NXDOMAIN, got %s", dns.RcodeToString[m.Rcode])
		return
	}
	// Authority section should contain the SOA record.
	for _, rr := range r.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			fmt.Println(soa.Serial)
		}
	}
}

// ExampleClient_Exchange_edns0 shows how to add an EDNS0 option to a message. See [dns.NSID].
func ExampleClient_Exchange_edns0() {
	m := dns.NewMsg("wwww.example.org", dns.TypeA)
	m.Pseudo = append(m.Pseudo, &dns.NSID{}) // we ask the server to put the server id in the reply.
	r, err := dns.Exchange(context.TODO(), m, "udp", "8.8.8.8:53")
	if err != nil {
		log.Printf("Failed to exchange: %v", err)
		return
	}
	for _, rr := range r.Pseudo {
		if nsid, ok := rr.(*dns.NSID); ok {
			fmt.Printf("NSID returned from server: %s\n", nsid.Nsid)
			break
		}
	}
}
