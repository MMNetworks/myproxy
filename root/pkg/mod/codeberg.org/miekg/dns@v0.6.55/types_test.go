package dns_test

import (
	"context"
	"fmt"
	"log"

	"codeberg.org/miekg/dns"
)

func ExampleA() {
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

func ExampleMX() {
	m := dns.NewMsg("example.org", dns.TypeMX)
	r, err := dns.Exchange(context.TODO(), m, "udp", "8.8.8.8:53")
	if err != nil {
		log.Printf("Failed to exchange: %v", err)
		return
	}
	for _, rr := range r.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			fmt.Println(mx.Preference, mx.Mx)
		}
	}
}
