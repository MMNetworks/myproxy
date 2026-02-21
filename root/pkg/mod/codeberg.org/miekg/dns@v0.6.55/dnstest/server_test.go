package dnstest

import (
	"context"
	"fmt"
	"log"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestServer(t *testing.T) {
	// mostly to check if it will not hang
	cancel, listen, err := Server(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	t.Logf("%s", listen)
}

func TestServerHTTP(t *testing.T) {
	cancel, listen, err := HTTPServer(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	t.Logf("%s", listen)
}

func ExampleTCPServer() {
	cancel, addr, _ := TCPServer(":0")
	defer cancel()

	m := NewMsg()
	r, err := dns.Exchange(context.TODO(), m, "tcp", addr)
	if err != nil {
		log.Fatalf("failed to exchange %s: %s", m.Question[0].Header().Name, err)
	}
	fmt.Println(r)
}
