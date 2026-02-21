package whoami_test

import (
	"context"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/atomtest"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/whoami"
	"codeberg.org/miekg/dns/dnstest"
)

func TestWhoami(t *testing.T) {
	w := new(whoami.Whoami)
	m := dnstest.NewMsg()

	tw := dnstest.NewTestRecorder()
	w.HandlerFunc(atomtest.Echo).ServeDNS(context.TODO(), tw, m)

	tw.Msg.Unpack()
	if len(tw.Msg.Answer) != 1 {
		t.Fatal("expected answer section")
	}
	if x := tw.Msg.Answer[0].(*dns.A).Addr.String(); x != dnstest.IPv4.String() {
		t.Fatalf("expected %q, got %q ", dnstest.IPv4.String(), x)
	}
}
