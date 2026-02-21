package dns_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/internal/bin"
	"codeberg.org/miekg/dns/internal/dnsfuzz"
)

// ExampleMsg_Question tests the creation of a small Msg with a question section only, and no EDNS0. This
// checks if we create the correct wire-format.
func ExampleMsg_Question() {
	m := &dns.Msg{MsgHeader: dns.MsgHeader{ID: 3, RecursionDesired: true}}
	mx := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}
	m.Question = []dns.RR{mx}

	m.Pack()
	fmt.Printf("%v\n", m.Data)
	// Output: [0 3 1 0 0 1 0 0 0 0 0 0 4 109 105 101 107 2 110 108 0 0 15 0 1]
}

func ExampleMsg_Pseudo_nsid() {
	m := &dns.Msg{MsgHeader: dns.MsgHeader{ID: 3, RecursionDesired: true}}
	m.Question = []dns.RR{&dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}}
	m.Pseudo = []dns.RR{&dns.NSID{}}

	m.Pack()
	// 41 is OPT after the zeros, 04 -> rdlength, 03 -> code of NSID, 00 -> "rdlength" of NSID
	fmt.Printf("%v\n", m.Data)
	// Output: [0 3 1 0 0 1 0 0 0 0 0 1 4 109 105 101 107 2 110 108 0 0 15 0 1 0 0 41 0 0 0 0 0 0 0 4 0 3 0 0]
}

func ExampleMsg() {
	m := dns.NewMsg("miek.nl.", dns.TypeMX)
	c := new(dns.Client)
	r, _, err := c.Exchange(context.TODO(), m, "udp", "127.0.0.1:53")
	if err != nil {
		log.Fatal(err)
	}
	if m, ok := r.Answer[0].(*dns.MX); ok {
		fmt.Println(m.Mx)
	}
	if n, ok := r.Pseudo[0].(*dns.NSID); ok {
		fmt.Println(n.Nsid)
	}
	for rr := range r.RRs() {
		fmt.Println(rr)
	}
}

func ExampleMsg_dNSSEC() {
	m := dns.NewMsg("miek.nl.", dns.TypeMX)
	m.UDPSize = dns.DefaultMsgSize
	m.Security = true
	dns.Exchange(context.TODO(), m, "udp", "127.0.0.1:53")
	// handle returned message.
}

func TestMsgBinary(t *testing.T) {
	tcs := []struct {
		name string
		buf  []byte
		fn   func(*dns.Msg) error
	}{
		{
			"edns0-subnet",
			[]byte{149, 112, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 1, 97, 4, 109, 105, 69, 75, 2, 78, 76, 0, 0, 1, 0, 1, 0, 0, 41, 5, 120, 0, 0, 128, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 14, 128, 63},
			func(m *dns.Msg) error {
				if len(m.Pseudo) == 0 {
					return errors.New("expected pseudo section")
				}
				s, ok := m.Pseudo[0].(*dns.SUBNET)
				if !ok {
					return errors.New("expected EDNS0 SUBNET")
				}
				const addr = "14.128.63.0"
				if s.Address != netip.MustParseAddr(addr) {
					return errors.New("expected address: " + addr)
				}
				return nil
			},
		},
		{
			"edns0-subnet",
			[]byte{255, 234, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 7, 99, 111, 114, 101, 68, 110, 83, 2, 105, 111, 0, 0, 28, 0, 1, 0, 0, 41, 5, 120, 0, 0, 128, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 0, 62, 212, 234},
			func(m *dns.Msg) error {
				if len(m.Pseudo) == 0 {
					return errors.New("expected pseudo section")
				}
				s, ok := m.Pseudo[0].(*dns.SUBNET)
				if !ok {
					return errors.New("expected EDNS0 SUBNET")
				}
				const addr = "62.212.234.0"
				if s.Address != netip.MustParseAddr(addr) {
					return errors.New("expected address: " + addr)
				}
				return nil
			},
		},
		{
			"opt-and-tsig",
			[]byte{148, 7, 1, 32, 0, 1, 0, 0, 0, 0, 0, 2, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 6, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 73, 65, 52, 201, 253, 43, 171, 193, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 93, 11, 104, 109, 97, 99, 45, 115, 104, 97, 53, 49, 50, 0, 0, 0, 105, 104, 143, 225, 1, 44, 0, 64, 195, 169, 191, 31, 144, 147, 160, 197, 245, 76, 217, 137, 234, 208, 246, 112, 113, 12, 208, 172, 99, 181, 29, 108, 140, 62, 197, 130, 116, 207, 127, 178, 163, 16, 242, 203, 41, 135, 60, 218, 187, 237, 181, 106, 91, 34, 125, 38, 190, 56, 117, 43, 76, 212, 161, 165, 61, 214, 193, 180, 117, 1, 27, 129, 148, 7, 0, 0, 0, 0},
			func(m *dns.Msg) error {
				if len(m.Pseudo) == 0 {
					return errors.New("expected pseudo section")
				}
				_, ok := m.Pseudo[len(m.Pseudo)-1].(*dns.TSIG)
				if !ok {
					return errors.New("expected TSIG")
				}
				return nil
			},
		},
		{
			"opt-and-tsig-extra-should-empty",
			[]byte{148, 7, 1, 32, 0, 1, 0, 0, 0, 0, 0, 2, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 6, 0, 1, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 73, 65, 52, 201, 253, 43, 171, 193, 4, 109, 105, 101, 107, 2, 110, 108, 0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 93, 11, 104, 109, 97, 99, 45, 115, 104, 97, 53, 49, 50, 0, 0, 0, 105, 104, 143, 225, 1, 44, 0, 64, 195, 169, 191, 31, 144, 147, 160, 197, 245, 76, 217, 137, 234, 208, 246, 112, 113, 12, 208, 172, 99, 181, 29, 108, 140, 62, 197, 130, 116, 207, 127, 178, 163, 16, 242, 203, 41, 135, 60, 218, 187, 237, 181, 106, 91, 34, 125, 38, 190, 56, 117, 43, 76, 212, 161, 165, 61, 214, 193, 180, 117, 1, 27, 129, 148, 7, 0, 0, 0, 0},
			func(m *dns.Msg) error {
				if len(m.Extra) != 0 {
					return errors.New("expected additional section to be empty")
				}
				return nil
			},
		},
		{
			"unknown-edns0-code20",
			//  edns20 := &dns.ERFC3597{EDNS0Code: 20, Code: hex.EncodeToString([]byte("hallo"))}
			//  m.Pseudo = append(m.Pseudo, edns20)
			[]byte{0, 3, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 111, 114, 103, 0, 0, 1, 0, 1, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 9, 0, 20, 0, 5, 104, 97, 108, 108, 111},
			func(m *dns.Msg) error {
				if len(m.Pseudo) != 1 {
					return errors.New("expected pseudo section to carry an option")
				}
				x := m.Pseudo[0].(*dns.ERFC3597)
				if x.EDNS0Code != 20 {
					return fmt.Errorf("expected code 20, got %d", x.EDNS0Code)
				}
				return nil
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			m := &dns.Msg{Data: tc.buf}
			if err := m.Unpack(); err != nil {
				t.Logf("%v\n", bin.Dump(m.Data))
				t.Fatal(err)
			}
			if err := tc.fn(m); err != nil {
				t.Logf("%s\n", bin.Dump(m.Data))
				t.Fatal(err)
			}
		})
	}
}

func TestMsgExtendedRcode(t *testing.T) {
	// set extended rcode, pack the message, unpack it, could should still be there. This tests _a lot_ as and OPT rr is allocated
	// and packed. Also during unpack the opposite is done.
	m := &dns.Msg{MsgHeader: dns.MsgHeader{ID: 3}}
	m.Question = []dns.RR{&dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET}}}
	m.Rcode = dns.RcodeBadTime

	m.Pack()
	r := new(dns.Msg)
	r.Data = m.Data
	r.Unpack()
	if r.Rcode != dns.RcodeBadTime {
		t.Errorf("expected %s, got %s", dns.RcodeToString[dns.RcodeBadTime], dns.RcodeToString[r.Rcode])
	}
}

func FuzzMsgPack(f *testing.F) {
	binaries := []string{"dig-mx-miek.nl", "dig+do+nsid-a-miek.nl"}
	for _, binary := range binaries {
		buf, _ := os.ReadFile("testdata/" + binary)
		f.Add(buf)
	}
	start := time.Now()
	f.Fuzz(func(t *testing.T, b []byte) {
		m := &dns.Msg{Data: b}
		m.Unpack()
		dnsfuzz.Stop(t, start)
	})
}

func TestMsgReadAll(t *testing.T) {
	m := dns.NewMsg("example.org.", dns.TypeA)
	m.Pack()

	done := make(chan struct{})
	go func() {
		io.ReadAll(m) // should not hang
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected io.ReadAll to complete, but hung")
	}
}
