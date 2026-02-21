package jump_test

import (
	"fmt"
	"os"
	"testing"

	"codeberg.org/miekg/dns/internal/bin"
	"codeberg.org/miekg/dns/internal/jump"
)

func TestName(t *testing.T) {
	testcases := []struct {
		buf   []byte
		start int
		off   int
	}{
		// miek.nl (4 miek 2 nl 0)
		{[]byte{4, 109, 105, 101, 107, 2, 110, 108, 0}, 0, 9},
		// beginning of a message, ID (98, 24),... then miek.nl as question = 0 15 (mx as type) and 0 01 as
		// class. But then 192 12 which is a pointer to miek.nl, so lets decode that.
		{[]byte{98, 24, 129, 128, 0, 1, 0, 5, 0, 0, 0, 1, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1, 192, 12, 0}, 25, 27},
		// Almost entire message... we are starting '192,12,0,15'; name pointer and then mx type.
		// 21,61 -> ttl, then 0,27 -> rdlength, 0, 5 -> mx prio, then 4,97...,5,95: alt1.aspmx.l.google.com.
		{[]byte{21, 33, 129, 128, 0, 1, 0, 5, 0, 0, 0, 1, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1, 192, 12, 0, 15, 0, 1, 0, 0, 21, 61, 0, 27, 0, 5, 4, 97, 108, 116, 49, 5, 97, 115, 112, 109, 120, 1, 108, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0}, 26, 64},
		// miek.nl (4 miek 2 nl), no null byte, should terminate.
		{[]byte{4, 109, 105, 101, 107, 2, 110, 108}, 2, 0},
	}
	for i, tc := range testcases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			off := jump.Name(tc.buf, tc.start)
			if off != tc.off {
				t.Errorf("expected offset %d, got %d", tc.off, off)
			}
		})
	}
}

func TestTo(t *testing.T) {
	testcases := []struct {
		binary string
		rrs    int
		off    int
	}{
		{"dig-mx-miek.nl", 0, 25},
		{"dig-mx-miek.nl", 1, 62},
		{"dig-mx-miek.nl", 2, 98},
		{"dig-mx-miek.nl", 3, 114},
		{"dig-mx-miek.nl", 4, 135},
		{"dig-mx-miek.nl", 5, 158}, // OPT RR
		{"dig-mx-miek.nl", 6, 0},   // overshoot
	}
	for i, tc := range testcases {
		t.Run(fmt.Sprintf("test %d: %s", i, tc.binary), func(t *testing.T) {
			buf, _ := os.ReadFile("../../testdata/" + tc.binary)
			off := jump.To(tc.rrs, buf)
			if off != tc.off {
				t.Errorf("expected to land on %d, got %d", tc.off, off)
				t.Logf("%v\n", buf[off:])
				t.Log(bin.Dump(buf))
			}
		})
	}
}

func TestToNoQuestion(t *testing.T) {
	// 2 identical MX (miek.nl. IN MX 10 mx.miek.nl.) in the answer section, qdcount is 0
	// created with
	//  m := new(dns.Msg)
	//  mx := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}, Preference: 10, Mx: "mx.miek.nl."}
	//  m.Answer = []dns.RR{mx, mx}
	//  m.Pack()
	//  println(bin.Bytes(m.Data))
	msg := []byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 15, 0, 1, 0, 0, 0, 0, 0, 7, 0, 10, 2, 109, 120, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 0, 0, 0, 4, 0, 10, 192, 33}
	testcases := []struct {
		to  int
		off int
	}{
		{0, 12},
		{1, 38},
		{2, 0},
	}
	for i, tc := range testcases {
		off := jump.To(tc.to, msg)
		if off != tc.off {
			t.Errorf("test %d, expected to land on %d, got %d", i, tc.off, off)
		}
	}
}
