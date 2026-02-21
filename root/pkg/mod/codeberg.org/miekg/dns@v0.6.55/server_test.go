package dns_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

func helloHandler(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, req)
	m.Extra = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: m.Question[0].Header().Name, Class: dns.ClassINET}, TXT: rdata.TXT{Txt: []string{"Hello world"}}}}
	io.Copy(w, m)
}

func anotherHelloHandler(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, req)
	m.Extra = []dns.RR{&dns.TXT{Hdr: dns.Header{Name: m.Question[0].Header().Name, Class: dns.ClassINET}, TXT: rdata.TXT{Txt: []string{"Hello example"}}}}
	io.Copy(w, m)
}

func TestServer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		addr    string
		run     func(laddr string, opts ...func(*dns.Server)) (func(), string, error)
	}{
		{"udp", "udp", ":0", dnstest.UDPServer},
		{"tcp", "tcp", ":0", dnstest.TCPServer},
		{"tcp-tls", "tcp", ":0", dnstest.TLSServer},
		{"unix", "unix", "/tmp/dns.sock", dnstest.Server},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dns.HandleFunc("miek.nl.", helloHandler)
			dns.HandleFunc("example.com.", anotherHelloHandler)
			defer dns.HandleRemove("miek.nl.")
			defer dns.HandleRemove("example.com.")

			opt := func(s *dns.Server) {}
			if tc.name == "unix" {
				opt = func(s *dns.Server) {
					s.Net = "unix"
					s.Listener, _ = net.Listen("unix", tc.addr)
				}
				defer os.Remove(tc.addr)
			}
			cancel, addr, err := tc.run(tc.addr, opt)
			if err != nil {
				t.Fatal(err)
			}
			defer cancel()

			c := &dns.Client{Transport: dns.NewTransport()}
			if tc.name == "tcp-tls" {
				c.TLSConfig = dnstest.TLSConfig()
			}

			m := new(dns.Msg)
			dnsutil.SetQuestion(m, "miek.nl.", dns.TypeTXT)
			m.Pack()

			r, _, err := c.Exchange(context.TODO(), m, tc.network, addr)
			if err != nil {
				t.Fatal("failed to exchange miek.nl.", err)
			}
			str := r.Extra[0].(*dns.TXT).Txt[0]
			if str != "Hello world" {
				t.Error("unexpected result for miek.nl.", str, "!= Hello world")
			}

			dnsutil.SetQuestion(m, "example.com.", dns.TypeTXT)
			m.Pack()

			r, _, err = c.Exchange(context.TODO(), m, tc.network, addr)
			if err != nil {
				t.Fatal("failed to exchange example.com.", err)
			}
			str = r.Extra[0].(*dns.TXT).Txt[0]
			if str != "Hello example" {
				t.Error("unexpected result for example.com.", str, "!= Hello example")
			}

			// Test Mixes cased as noticed by Ask.
			dnsutil.SetQuestion(m, "eXaMPlE.cOm.", dns.TypeTXT)
			m.Pack()

			r, _, err = c.Exchange(context.TODO(), m, tc.network, addr)
			if err != nil {
				t.Error("failed to exchange eXaMplE.cOm.", err)
			}
			str = r.Extra[0].(*dns.TXT).Txt[0]
			if str != "Hello example" {
				t.Error("unexpected result for example.com.", str, "!= Hello example")
			}
		})
	}
}

// Verify that the server responds to a query with Z flag on, ignoring the flag, and does not echoes it back.
func TestServerZFlag(t *testing.T) {
	dns.HandleFunc("example.com.", helloHandler)
	defer dns.HandleRemove("example.com.")
	cancel, addr, _ := dnstest.UDPServer(":0")
	defer cancel()

	m := new(dns.Msg)
	dnsutil.SetQuestion(m, "example.com.", dns.TypeTXT)
	m.Zero = true
	m.Pack()

	r, err := dns.Exchange(context.TODO(), m, "udp", addr)
	if err != nil {
		t.Fatal("failed to exchange example.com. with +zflag", err)
	}
	if r.Zero {
		t.Error("the response should not have Z flag set - even for a query which does")
	}
	if r.Rcode != dns.RcodeSuccess {
		t.Errorf("expected rcode %v, got %v", dns.RcodeSuccess, r.Rcode)
	}
}

func TestServerMsgInvalidFunc(t *testing.T) {
	dns.HandleFunc("example.org.", func(context.Context, dns.ResponseWriter, *dns.Msg) {
		t.Fatal("the handler must not be called in any of these tests")
	})

	invalidErrors := make(chan error)
	cancel, addr, _ := dnstest.TCPServer(":0", func(srv *dns.Server) {
		srv.MsgInvalidFunc = func(m *dns.Msg, err error) {
			invalidErrors <- err
		}
	})
	defer cancel()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("cannot connect to test server: %v", err)
	}

	write := func(m []byte) {
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l[0:], uint16(len(m)))
		m = append(l, m...)
		if _, err = c.Write(m); err != nil {
			t.Fatalf("message write failed: %v", err)
		}
	}

	// Message is too short, so there is no header to accept or reject.
	tooShortMessage := make([]byte, 11)

	write(tooShortMessage)
	<-invalidErrors // Expect an error to be reported.

	badMessage := make([]byte, 13)
	badMessage[1] = 0x1 // ID = 1, Accept.
	badMessage[5] = 1   // QDCOUNT = 1
	badMessage[12] = 99 // Bad question section.  Invalid!

	write(badMessage)
	<-invalidErrors // Expect an error to be reported.
}
