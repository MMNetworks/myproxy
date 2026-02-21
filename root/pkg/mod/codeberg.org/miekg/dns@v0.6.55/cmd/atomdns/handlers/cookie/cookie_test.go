package cookie_test

import (
	"context"
	"encoding/hex"
	"hash/fnv"
	"io"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/atomtest"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/cookie"
	"codeberg.org/miekg/dns/dnstest"
)

func TestCookie(t *testing.T) {
	c := &cookie.Cookie{Secret: "geheim"}

	f := fnv.New64()
	io.WriteString(f, "::1")
	io.WriteString(f, "::1")
	io.WriteString(f, "ook geheim")
	cookie := &dns.COOKIE{Cookie: hex.EncodeToString(f.Sum(nil))}

	m := dnstest.NewMsg()
	m.Pseudo = []dns.RR{cookie}
	m.Pack()

	tw := dnstest.NewTestRecorder()
	c.HandlerFunc(atomtest.Echo).ServeDNS(context.TODO(), tw, m)

	tw.Msg.Unpack()
	if len(tw.Msg.Pseudo) != 1 {
		t.Fatal("expected pseudo section")
	}
	if _, ok := tw.Msg.Pseudo[0].(*dns.COOKIE); !ok {
		t.Fatal("expected COOKIE RR")
	}
}
