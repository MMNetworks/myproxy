package dnstest

import (
	"io"
	"testing"

	"codeberg.org/miekg/dns"
)

func TestRecorder(t *testing.T) {
	m := new(dns.Msg)
	m.Question = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}}

	rec := NewRecorder(nil)
	io.Copy(rec, m)
	rec.Msg.Unpack()
	if x := rec.Msg.Question[0].Header().Name; x != "miek.nl." {
		t.Errorf("expected %s, got %s", "miek.nl.", x)
	}
}

func TestMultiRecorder(t *testing.T) {
	m := new(dns.Msg)
	m.Question = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}}

	rec := NewMultiRecorder(nil)
	io.Copy(rec, m)
	io.Copy(rec, m)
	if len(rec.Msgs) != 2 {
		t.Errorf("expeced 2 messages, got %d", len(rec.Msgs))
	}
	rec.Msg.Unpack()
	if x := rec.Msg.Question[0].Header().Name; x != "miek.nl." {
		t.Errorf("expected %s, got %s", "miek.nl.", x)
	}
}
