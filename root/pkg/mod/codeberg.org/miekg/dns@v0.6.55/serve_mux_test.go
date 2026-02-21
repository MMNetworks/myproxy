package dns

import (
	"context"
	"testing"
)

func TestServeMuxDSRouting(t *testing.T) {
	mux := NewServeMux()
	noopHandler := func(ctx context.Context, w ResponseWriter, req *Msg) {}
	mux.Handle("child.miek.nl.", HandlerFunc(noopHandler))
	mux.Handle("miek.nl.", HandlerFunc(noopHandler))
	mux.Handle(".", HandlerFunc(noopHandler)) // previously you would get this..

	_, zone := mux.match("child.miek.nl.", TypeTXT)
	if zone != "child.miek.nl." {
		t.Errorf("expected %s, got %s", "child.miek.nl. for TXT", zone)
	}
	_, zone = mux.match("miek.nl.", TypeDS) // there is no parent
	if zone != "miek.nl." {
		t.Errorf("expected %s, got %s", "miek.nl. for DS", zone)
	}
	_, zone = mux.match("child.miek.nl.", TypeDS) // miek.nl is the parent
	if zone != "miek.nl." {
		t.Errorf("expected %s, got %s", "miek.nl. for DS", zone)
	}
}

func BenchmarkServeMux(b *testing.B) {
	mux := NewServeMux()
	noopHandler := func(ctx context.Context, w ResponseWriter, req *Msg) {}
	mux.Handle("_udp.example.org.", HandlerFunc(noopHandler))

	for b.Loop() {
		mux.match("_dns._udp.example.com.", TypeSRV)
		mux.match("miek.nl.", TypeSRV)
	}
}
