package atom_test

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/atomtest"
)

func TestServer(t *testing.T) {
	_, cancel, err := atomtest.New(`
example.org {
	log
}
example.org {
	log
}
`)
	if err == nil {
		cancel()
		t.Fatalf("expected 'origin already registered' error, got none")
	}
}
