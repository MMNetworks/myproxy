package dns_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

var testTransferData = []dns.RR{
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032800 21600 7200 604800 3600"),
	dnstest.New("x.miek.nl. IN A 10.0.0.1"),
	dnstest.New("miek.nl. IN MX 1 x.miek.nl."),
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032800 21600 7200 604800 3600"),
}

var testTransferDataIncrementalData = []dns.RR{
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600"),
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032800 21600 7200 604800 3600"),
	dnstest.New("x.miek.nl. IN A 10.0.0.1"),
	dnstest.New("miek.nl. IN MX 1 x.miek.nl."),
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600"),
	dnstest.New("x.miek.nl. IN A 10.0.0.5"),
	dnstest.New("miek.nl. IN MX 10 x.miek.nl."),
	dnstest.New("miek.nl. IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600"),
}

const testTransferZone = "miek.nl."

func TestTransferEdgeCases(t *testing.T) {
	single := false
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		r.Unpack()
		w.Hijack()

		env := make(chan *dns.Envelope)
		c := new(dns.Client)

		var wg sync.WaitGroup
		wg.Go(func() {
			c.TransferOut(w, r, env)
		})
		if single {
			env <- &dns.Envelope{Answer: []dns.RR{testTransferData[0]}}
		} else {
			env <- &dns.Envelope{Answer: []dns.RR{}}
		}
		close(env)
		w.Close()
	})
	defer dns.HandleRemove(testTransferZone)

	for _, name := range []string{"invalid", "single"} {
		t.Run(name, func(t *testing.T) {
			if name == "single" {
				single = true
			}
			cancel, addr, _ := dnstest.TCPServer(":0")
			defer cancel()

			c := new(dns.Client)
			m := new(dns.Msg)
			dnsutil.SetQuestion(m, testTransferZone, dns.TypeAXFR)

			env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
			if err != nil {
				t.Fatal("failed to zone transfer in", err)
			}

			for e := range env {
				if !single && e.Error == nil {
					t.Fatal("expected error, got none")
				}
				if single && len(e.Answer) != 1 {
					t.Fatalf("bad axfr: expected %d, got %d", 1, len(e.Answer))
				}
			}
		})
	}
}

func TestTransfer(t *testing.T) {
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		r.Unpack()
		w.Hijack()

		env := make(chan *dns.Envelope)
		c := dns.NewClient()

		var wg sync.WaitGroup
		wg.Go(func() {
			err := c.TransferOut(w, r, env)
			if err != nil {
				t.Fatal(err)
			}
			w.Close()
		})
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[0]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[1]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[2]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[3]}}
		close(env)
	})
	defer dns.HandleRemove(testTransferZone)

	for _, name := range []string{"tcp", "tcp-tls", "tcp-ixfr", "tcp-tls-ixfr"} {
		t.Run(name, func(t *testing.T) {
			c := dns.NewClient()
			m := dns.NewMsg(testTransferZone, dns.TypeAXFR)
			ixfrsoa := []dns.RR{&dns.SOA{Hdr: *m.Question[0].Header(), SOA: rdata.SOA{Ns: ".", Mbox: ".", Serial: 2009032799}}}
			addr := ""
			switch name {
			case "tcp", "tcp-ixfr":
				cancel, adr, _ := dnstest.TCPServer(":0")
				defer cancel()
				addr = adr
				if strings.HasSuffix(name, "-ixfr") {
					m = dns.NewMsg(testTransferZone, dns.TypeIXFR)
					m.Ns = ixfrsoa
				}
			case "tcp-tls", "tcp-tls-ixfr":
				cancel, adr, _ := dnstest.TLSServer(":0")
				defer cancel()
				addr = adr
				c.TLSConfig = dnstest.TLSConfig()
				if strings.HasSuffix(name, "-ixfr") {
					m = dns.NewMsg(testTransferZone, dns.TypeIXFR)
					m.Ns = ixfrsoa
				}
			}

			env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
			if err != nil {
				t.Fatal("failed to setup zone transfer in", err)
			}

			i := 0
			for e := range env {
				if e.Error != nil {
					t.Errorf("unexpected error: %s", e.Error)
					break
				}
				i += len(e.Answer)
			}
			if i != len(testTransferData) {
				t.Fatalf("bad axfr: expected %d, got %d", len(testTransferData), i)
			}
		})
	}
}

func TestTransferIncrementalEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		answers [][]dns.RR
		serial  uint32
		wantErr bool
		want    int
	}{
		{"invalid", [][]dns.RR{{}}, 2009032802, true, 0},
		{"not-soa", [][]dns.RR{{testTransferData[1]}}, 2009032802, true, 0},
		{"single", [][]dns.RR{{testTransferData[0]}}, 2009032800, false, 1},
		{
			"up-to-date", [][]dns.RR{
				testTransferDataIncrementalData[:len(testTransferDataIncrementalData)/2],
				testTransferDataIncrementalData[len(testTransferDataIncrementalData)/2:],
			}, 2009032802, false, 1,
		},
	}

	var answers [][]dns.RR
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		r.Unpack()
		w.Hijack()

		env := make(chan *dns.Envelope)
		c := new(dns.Client)

		var wg sync.WaitGroup
		wg.Go(func() {
			c.TransferOut(w, r, env)
		})

		for _, ans := range answers {
			env <- &dns.Envelope{Answer: ans}
		}

		close(env)
	})
	defer dns.HandleRemove(testTransferZone)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answers = tt.answers
			cancel, addr, _ := dnstest.TCPServer(":0")
			defer cancel()

			c := new(dns.Client)
			m := dns.NewMsg(testTransferZone, dns.TypeIXFR)
			m.Ns = []dns.RR{&dns.SOA{Hdr: *m.Question[0].Header(), SOA: rdata.SOA{Ns: ".", Mbox: ".", Serial: tt.serial}}}

			env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
			if err != nil {
				t.Fatal("failed to zone transfer in", err)
			}

			var (
				gotErr error
				i      = 0
			)
			for e := range env {
				if e.Error != nil {
					gotErr = e.Error
				}
				i += len(e.Answer)
			}

			if gotErr == nil && tt.wantErr {
				t.Fatal("expected error, got none")
			}
			if gotErr != nil && !tt.wantErr {
				t.Fatalf("unexpected error: %s", gotErr)
			}
			if i != tt.want {
				t.Fatalf("bad ixfr: expected %d, got %d", tt.want, i)
			}
		})
	}
}

func TestTransferIncremental(t *testing.T) {
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		r.Unpack()
		w.Hijack()

		env := make(chan *dns.Envelope)
		c := dns.NewClient()

		var wg sync.WaitGroup
		wg.Go(func() {
			err := c.TransferOut(w, r, env)
			if err != nil {
				t.Fatal(err)
			}
			w.Close()
		})

		env <- &dns.Envelope{Answer: testTransferDataIncrementalData[:len(testTransferDataIncrementalData)/2]}
		env <- &dns.Envelope{Answer: testTransferDataIncrementalData[len(testTransferDataIncrementalData)/2:]}
		close(env)
	})
	defer dns.HandleRemove(testTransferZone)

	for _, name := range []string{"tcp", "tcp-tls"} {
		t.Run(name, func(t *testing.T) {
			c := dns.NewClient()
			m := dns.NewMsg(testTransferZone, dns.TypeIXFR)
			m.Ns = []dns.RR{&dns.SOA{Hdr: *m.Question[0].Header(), SOA: rdata.SOA{Ns: ".", Mbox: ".", Serial: 2009032800}}}

			addr := ""
			switch name {
			case "tcp":
				cancel, adr, _ := dnstest.TCPServer(":0")
				defer cancel()
				addr = adr
			case "tcp-tls":
				cancel, adr, _ := dnstest.TLSServer(":0")
				defer cancel()
				addr = adr
				c.TLSConfig = dnstest.TLSConfig()
			}

			env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
			if err != nil {
				t.Fatal("failed to setup zone transfer in", err)
			}

			i := 0
			for e := range env {
				if e.Error != nil {
					t.Fatalf("unexpected error: %s", e.Error)
				}
				i += len(e.Answer)
			}
			if i != len(testTransferDataIncrementalData) {
				t.Fatalf("bad ixfr: expected %d, got %d", len(testTransferDataIncrementalData), i)
			}
		})
	}
}

func TestTransferTSIG(t *testing.T) {
	dns.HandleFunc(testTransferZone, func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		r.Unpack()
		w.Hijack()

		var wg sync.WaitGroup
		env := make(chan *dns.Envelope)
		c := dns.NewClient()
		c.Transfer = &dns.Transfer{TSIGSigner: dns.HmacTSIG{[]byte("geheim")}}
		wg.Go(func() {
			err := c.TransferOut(w, r, env)
			if err != nil {
				t.Fatal(err)
			}
			w.Close()
		})
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[0]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[1]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[2]}}
		env <- &dns.Envelope{Answer: []dns.RR{testTransferData[3]}}
		close(env)
	})
	defer dns.HandleRemove(testTransferZone)

	cancel, addr, _ := dnstest.TCPServer(":0")
	defer cancel()

	c := dns.NewClient()
	c.Transfer = &dns.Transfer{TSIGSigner: dns.HmacTSIG{[]byte("geheim")}}

	m := dns.NewMsg(testTransferZone, dns.TypeAXFR)
	m.Pseudo = []dns.RR{dns.NewTSIG(".", dns.HmacSHA512, 0)}

	env, err := c.TransferIn(context.TODO(), m, "tcp", addr)
	if err != nil {
		t.Fatal("failed to zone transfer in", err)
	}

	for e := range env {
		if e.Error != nil {
			t.Fatal(e.Error)
		}
	}
}
