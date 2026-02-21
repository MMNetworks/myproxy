package atomtest

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestServer(t *testing.T) {
	input := `example.org {
	whoami
}`

	s, cancel, err := New(input)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	c := new(dns.Client)
	m := dns.NewMsg("whoami.example.org.", dns.TypeA)
	r, _, err := c.Exchange(context.TODO(), m, "udp", s.Addr()[0])
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	for rr := range r.RRs() {
		if rr.Header().Name != "whoami.example.org." {
			t.Errorf("expected %q, got %q", "whoami.example.org.", rr.Header().Name)
		}
		switch i {
		case 1:
			_, ok1 := rr.(*dns.A)
			_, ok2 := rr.(*dns.AAAA)
			if !ok1 && !ok2 {
				t.Error("expected A or AAAA, got something else")
			}
		case 2:
			if x, ok := rr.(*dns.TXT); !ok {
				t.Errorf("expected TXT, got %T, %s", x, rr)
			}
		}
		i++
	}
}
