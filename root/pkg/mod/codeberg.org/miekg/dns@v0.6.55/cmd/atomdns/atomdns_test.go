package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/atomtest"
	"codeberg.org/miekg/dns/internal/dnsperf"
)

const Conffile = `
{
	dns {
		addr [::]:%s
	}
}

whoami.example.org {
    whoami
}
`

func TestAtomdnsPerf(t *testing.T) {
	const count = 8
	ports := [2]string{"8053", "8054"}
	dir := t.TempDir()
	conffile := dir + "/Conffile"

	for p, network := range []string{"udp", "tcp"} {
		os.WriteFile(conffile, fmt.Appendf(nil, Conffile, ports[p]), 0600)

		t.Run("atomdns-"+network, func(t *testing.T) {
			timeout := count*2*time.Second + 5*time.Second
			ctx, cancel := context.WithTimeout(context.Background(), timeout)

			if _, err := os.Stat("./atomdns"); err != nil {
				t.Skip("no atomdns binary found in .")
			}

			cmd := exec.CommandContext(ctx, "./atomdns", conffile)
			go func() {
				if err := cmd.Run(); err != nil {
					if _, ok := err.(*exec.ExitError); !ok {
						log.Fatal("no working atomdns binary found in .")
					}
				}
			}()

			queries := strings.NewReader("whoami.example.org. A")
			if err := dnsperf.Run(t, queries, fmt.Sprintf("127.0.0.1:%s", ports[p]), network, 2*time.Second, count); err != nil {
				t.Fatal(err)
			}
			t.Logf("canceled executing: %s", network)
			cancel()
		})
	}
}

func TestAtomdns(t *testing.T) {
	testcases := []struct {
		qname     string
		qtype     uint16
		answerlen int
	}{
		{"www.example.org.", dns.TypeA, 2},
	}
	s, cancel, err := atomtest.New(`
10.0.0.0/24 {
    log
    whoami
}

example.org {
    log
    dbfile handlers/dbfile/zone/testdata/db.example.org {
        transfer
    }
}
`)
	defer cancel()
	if err != nil {
		t.Fatal(err)
	}

	c := new(dns.Client)
	for _, tc := range testcases {
		t.Run(tc.qname+"/"+dns.TypeToString[tc.qtype], func(t *testing.T) {
			m := dns.NewMsg(tc.qname, dns.TypeA)
			r, _, err := c.Exchange(context.TODO(), m, "udp", s.Addr()[0])
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Answer) != tc.answerlen {
				t.Fatalf("expected %d answers, got %d", tc.answerlen, len(r.Answer))
			}
		})
	}

	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range testcases {
		t.Run("reload/"+tc.qname+"/"+dns.TypeToString[tc.qtype], func(t *testing.T) {
			m := dns.NewMsg(tc.qname, dns.TypeA)
			r, _, err := c.Exchange(context.TODO(), m, "udp", s.Addr()[0])
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Answer) != tc.answerlen {
				t.Fatalf("expected %d answers, got %d", tc.answerlen, len(r.Answer))
			}
		})
	}
}
