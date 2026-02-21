package dnsutil_test

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func TestIsRRset(t *testing.T) {
	testcases := []struct {
		name string
		rrs  []dns.RR
		ok   bool
	}{
		{
			"good",
			[]dns.RR{
				&dns.TXT{Hdr: dns.Header{Name: "name.cloudflare.com.", Class: dns.ClassINET}, TXT: rdata.TXT{Txt: []string{"Hello world"}}},
				&dns.TXT{Hdr: dns.Header{Name: "name.cloudflare.com.", Class: dns.ClassINET}, TXT: rdata.TXT{Txt: []string{"_o/"}}},
			},
			true,
		},
		{
			"inconsitentname",
			[]dns.RR{
				&dns.TXT{Hdr: dns.Header{Name: "name.cloudflare.com.", Class: dns.ClassINET}, TXT: rdata.TXT{Txt: []string{"Hello world"}}},
				&dns.TXT{Hdr: dns.Header{Name: "nama.cloudflare.com.", Class: dns.ClassINET}, TXT: rdata.TXT{Txt: []string{"_o/"}}},
			},
			false,
		},
		{
			"inconsitenttype",
			[]dns.RR{
				&dns.TXT{Hdr: dns.Header{Name: "name.cloudflare.com.", Class: dns.ClassINET}, TXT: rdata.TXT{Txt: []string{"Hello world"}}},
				&dns.A{Hdr: dns.Header{Name: "nama.cloudflare.com.", Class: dns.ClassINET}},
			},
			false,
		},
		{
			"inconsitentclass",
			[]dns.RR{
				&dns.TXT{Hdr: dns.Header{Name: "name.cloudflare.com.", Class: dns.ClassINET}, TXT: rdata.TXT{Txt: []string{"Hello world"}}},
				&dns.TXT{Hdr: dns.Header{Name: "nama.cloudflare.com.", Class: dns.ClassCHAOS}, TXT: rdata.TXT{Txt: []string{"_o/"}}},
			},
			false,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := dnsutil.IsRRset(tc.rrs)
			if got != tc.ok {
				t.Fatalf("expected %t, got %t", tc.ok, got)
			}
		})
	}
}

func TestIsName(t *testing.T) {
	testcases := []struct {
		in string
		ok bool
	}{
		{`www\.this.is.\131an.example.org.`, true},
		{`www.example.org.`, true},
		{`www.example.org`, true},
		{`org.`, true},
		{`.`, true},
		{`..`, false},
		{`.org`, false},
		{`www..example.org.`, false},
		{`www.example.org..`, false},
	}
	for _, tc := range testcases {
		got := dnsutil.IsName(tc.in)
		if got != tc.ok {
			t.Errorf("expected %t for name %q", tc.ok, tc.in)
		}
	}
}
