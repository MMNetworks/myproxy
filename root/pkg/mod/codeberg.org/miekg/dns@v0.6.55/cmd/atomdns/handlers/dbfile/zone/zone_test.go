package zone

import (
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnstest"
)

func TestZone(t *testing.T) {
	z := New("example.org.", "testdata/db.example.org")
	if err := z.Load(); err != nil {
		t.Fatal(err)
	}
	testcases := []struct {
		name string
		in   func() *dns.Msg
		exp  func() *dns.Msg
	}{
		{
			"dns:apex",
			func() *dns.Msg { m := dns.NewMsg("example.org.", dns.TypeNS); return m },
			func() *dns.Msg {
				m := dns.NewMsg("example.org.", dns.TypeNS)
				m.Answer = []dns.RR{
					dnstest.New("example.org.    IN NS      a.iana-servers.net."),
					dnstest.New("example.org.    IN NS      b.iana-servers.net."),
				}
				return m
			},
		},
		{
			"dns:case:apex",
			func() *dns.Msg { m := dns.NewMsg("EXAMPLE.org.", dns.TypeNS); return m },
			func() *dns.Msg {
				m := dns.NewMsg("example.org.", dns.TypeNS)
				m.Answer = []dns.RR{
					dnstest.New("example.org.    IN NS      a.iana-servers.net."),
					dnstest.New("example.org.    IN NS      b.iana-servers.net."),
				}
				return m
			},
		},
		{
			"dns:exact",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeA)
				m.Answer = []dns.RR{
					dnstest.New("a.example.org.  IN A       139.162.196.78"),
				}
				return m
			},
		},
		{
			"dns:case:exact",
			func() *dns.Msg { m := dns.NewMsg("A.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeA)
				m.Answer = []dns.RR{
					dnstest.New("a.example.org.  IN A       139.162.196.78"),
				}
				return m
			},
		},
		{
			"dnssec:exact",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeA)
				m.Answer = []dns.RR{
					dnstest.New("a.example.org.  IN A       139.162.196.78"),
					dnstest.New("a.example.org.  IN RRSIG   A 13 3 1800 20161129153240 20161030153240 49035 example.org. 41jFz0Dr8tZBN4Kv25S5dD4vTmviFiLx7xSAqMIuLFm0qibKL07perKpxqgLqM0H1wreT4xzI9Y4Dgp1nsOuMA=="),
				}
				return m
			},
		},
		{
			"dns:delegation",
			func() *dns.Msg { m := dns.NewMsg("a.delegated.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.delegated.example.org.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("delegated.example.org.  IN NS   a.delegated.example.org."),
					dnstest.New("delegated.example.org.  IN NS   ns-ext.nlnetlabs.nl."),
				}
				m.Extra = []dns.RR{
					dnstest.New("a.delegated.example.org. IN A       139.162.196.78"),
					dnstest.New("a.delegated.example.org. IN AAAA    2a01:7e00::f03c:91ff:fef1:6735"),
				}
				return m
			},
		},
		{
			"dnssec:delegation",
			func() *dns.Msg { m := dns.NewMsg("a.delegated.example.org.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.delegated.example.org.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("delegated.example.org. IN NS     a.delegated.example.org."),
					dnstest.New("delegated.example.org. IN NS     ns-ext.nlnetlabs.nl."),
					dnstest.New("delegated.example.org. IN DS	  10056 5 1 EE72CABD1927759CDDA92A10DBF431504B9E1F13"),
					dnstest.New("delegated.example.org. IN DS	  10056 5 2 E4B05F87725FA86D9A64F1E53C3D0E6250946599DFE639C45955B0ED416CDDFA"),
					dnstest.New("delegated.example.org. IN RRSIG   DS 13 3 1800 20161129153240 20161030153240 49035 example.org. rlNNzcUmtbjLSl02ZzQGUbWX75yCUx0Mug1jHtKVqRq1hpPE2S3863tIWSlz+W9wz4o19OI4jbznKKqk+DGKog=="),
				}
				m.Extra = []dns.RR{
					dnstest.New("a.delegated.example.org. IN A       139.162.196.78"),
					dnstest.New("a.delegated.example.org. IN AAAA    2a01:7e00::f03c:91ff:fef1:6735"),
				}
				return m
			},
		},
		{
			"dnssec:insecuredelegation",
			func() *dns.Msg { m := dns.NewMsg("a.sub.example.org.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.sub.example.org.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("sub.example.org. IN NS   sub1.example.net."),
					dnstest.New("sub.example.org. IN NS   sub2.example.net."),
					dnstest.New("sub.example.org. IN NSEC www.example.org. NS RRSIG NSEC"),
					dnstest.New("sub.example.org. IN RRSIG NSEC 13 3 14400 20161129153240 20161030153240 49035 example.org. VYjahdV+TTkA3RBdnUI0hwXDm6U5k/weeZZrix1znORpOELbeLBMJW56cnaG+LGwOQfw9qqjbOuULDst84s4+g=="),
				}
				return m
			},
		},
		{
			"dns:nodata",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeTXT); return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeTXT)
				m.Ns = []dns.RR{
					dnstest.New("example.org. IN SOA  a.iana-servers.net. devnull.example.org. 1282630057 14400 3600 604800 14400"),
				}
				return m
			},
		},
		{
			"dnssec:nodata",
			func() *dns.Msg { m := dns.NewMsg("a.example.org.", dns.TypeTXT); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("a.example.org.", dns.TypeTXT)
				m.Ns = []dns.RR{
					dnstest.New("example.org. IN SOA     a.iana-servers.net. devnull.example.org. 1282630057 14400 3600 604800 14400"),
					dnstest.New("example.org. IN RRSIG   SOA 13 2 1800 20161129153240 20161030153240 49035 example.org. GVnMpFmN+6PDdgCtlYDEYBsnBNDgYmEJNvosBk9+PNTPNWNst+BXCpDadTeqRwrr1RHEAQ7jYWzNwqn81pN+IA=="),
					dnstest.New("example.org. IN NSEC    a.example.org. NS SOA RRSIG NSEC DNSKEY"),
					dnstest.New("example.org. IN RRSIG   NSEC 13 2 14400 20161129153240 20161030153240 49035 example.org. BQROf1swrmYi3GqpP5M/h5vTB8jmJ/RFnlaX7fjxvV7aMvXCsr3ekWeB2S7L6wWFihDYcKJg9BxVPqxzBKeaqg=="),
				}
				return m
			},
		},
		{
			"dns:nxdomain",
			func() *dns.Msg { m := dns.NewMsg("www1.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("www1.example.org.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("example.org. IN SOA  a.iana-servers.net. devnull.example.org. 1282630057 14400 3600 604800 14400"),
				}
				return m
			},
		},
		{
			"dnssec:nxdomain",
			func() *dns.Msg { m := dns.NewMsg("www1.example.org.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("www1.example.org.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("example.org. IN SOA  a.iana-servers.net. devnull.example.org. 1282630057 14400 3600 604800 14400"),
					dnstest.New("example.org. IN RRSIG   SOA 13 2 1800 20161129153240 20161030153240 49035 example.org. GVnMpFmN+6PDdgCtlYDEYBsnBNDgYmEJNvosBk9+PNTPNWNst+BXCpDadTeqRwrr1RHEAQ7jYWzNwqn81pN+IA=="),
					dnstest.New("example.org. IN NSEC    a.example.org. NS SOA RRSIG NSEC DNSKEY"),
					dnstest.New("example.org. IN RRSIG   NSEC 13 2 14400 20161129153240 20161030153240 49035 example.org. BQROf1swrmYi3GqpP5M/h5vTB8jmJ/RFnlaX7fjxvV7aMvXCsr3ekWeB2S7L6wWFihDYcKJg9BxVPqxzBKeaqg=="),
					dnstest.New("www.example.org. IN NSEC    example.org. CNAME RRSIG NSEC"),
					dnstest.New("www.example.org. IN RRSIG   NSEC 13 3 14400 20161129153240 20161030153240 49035 example.org. jy3f96GZGBaRuQQjuqsoP1YN8ObZF37o+WkVPL7TruzI7iNl0AjrUDy9FplP8Mqk/HWyvlPeN3cU+W8NYlfDDQ=="),
				}
				return m
			},
		},
		{
			"dns:cname",
			func() *dns.Msg { m := dns.NewMsg("archive.example.org.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("archive.example.org.", dns.TypeA)
				m.Answer = []dns.RR{
					dnstest.New("archive.example.org. IN CNAME   a.example.org."),
					dnstest.New("a.example.org.       IN A       139.162.196.78"),
				}
				return m
			},
		},
		{
			"dns:cname6",
			func() *dns.Msg { m := dns.NewMsg("archive.example.org.", dns.TypeAAAA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("archive.example.org.", dns.TypeAAAA)
				m.Answer = []dns.RR{
					dnstest.New("archive.example.org. IN CNAME   a.example.org."),
					dnstest.New("a.example.org.  IN AAAA    2a01:7e00::f03c:91ff:fef1:6735"),
				}
				return m
			},
		},
		{
			"dnssec:cname",
			func() *dns.Msg { m := dns.NewMsg("archive.example.org.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("archive.example.org.", dns.TypeA)
				m.Answer = []dns.RR{
					dnstest.New("archive.example.org. IN CNAME   a.example.org."),
					dnstest.New("archive.example.org. IN RRSIG   CNAME 13 3 1800 20161129153240 20161030153240 49035 example.org. SDFW1z/PN9knzH8BwBvmWK0qdIwMVtGrMgRw7lgy4utRrdrRdCSLZy3xpkmkh1wehuGc4R0S05Z3DPhB0Fg5BA=="),
					dnstest.New("a.example.org. IN A       139.162.196.78"),
					dnstest.New("a.example.org. IN RRSIG   A 13 3 1800 20161129153240 20161030153240 49035 example.org. 41jFz0Dr8tZBN4Kv25S5dD4vTmviFiLx7xSAqMIuLFm0qibKL07perKpxqgLqM0H1wreT4xzI9Y4Dgp1nsOuMA=="),
				}
				return m
			},
		},
		{
			"dnssec:cname6",
			func() *dns.Msg { m := dns.NewMsg("archive.example.org.", dns.TypeAAAA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("archive.example.org.", dns.TypeAAAA)
				m.Answer = []dns.RR{
					dnstest.New("archive.example.org. IN CNAME   a.example.org."),
					dnstest.New("archive.example.org. IN RRSIG   CNAME 13 3 1800 20161129153240 20161030153240 49035 example.org. SDFW1z/PN9knzH8BwBvmWK0qdIwMVtGrMgRw7lgy4utRrdrRdCSLZy3xpkmkh1wehuGc4R0S05Z3DPhB0Fg5BA=="),
					dnstest.New("a.example.org.  IN AAAA    2a01:7e00::f03c:91ff:fef1:6735"),
					dnstest.New("a.example.org.  IN RRSIG   AAAA 13 3 1800 20161129153240 20161030153240 49035 example.org. brHizDxYCxCHrSKIu+J+XQbodRcb7KNRdN4qVOWw8wHqeBsFNRzvFF6jwPQYphGP7kZh1KAbVuY5ZVVhM2kHjw=="),
				}
				return m
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			expmsg := tc.exp()
			exprrs := []dns.RR{}
			for rr := range expmsg.RRs() {
				exprrs = append(exprrs, rr)
			}

			rmsg := dnszone.Retrieve(z, tc.in(), nil)
			gotrrs := []dns.RR{}
			for rr := range rmsg.RRs() {
				gotrrs = append(gotrrs, rr)
			}
			if !rmsg.Authoritative && !strings.Contains(tc.name, "delegation") {
				t.Fatal("expected AA data")
			}
			if len(exprrs) != len(gotrrs) {
				t.Errorf("expected %d RRs, got %d", len(exprrs), len(gotrrs))
				t.Logf("%s", rmsg)
			}
			for i := range gotrrs {
				if !dns.Equal(gotrrs[i], exprrs[i]) {
					t.Logf("%s", rmsg)
					t.Fatalf("expected %q and %q to be equal", gotrrs[i], exprrs[i])
				}
			}
		})
	}
}

func TestZoneWildcard(t *testing.T) {
	z := New("example.", "testdata/db.example")
	if err := z.Load(); err != nil {
		t.Fatal(err)
	}
	testcases := []struct {
		name string
		in   func() *dns.Msg
		exp  func() *dns.Msg
	}{
		{
			"dns:entbogus",
			func() *dns.Msg { m := dns.NewMsg("bogus.example.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("bogus.example.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("example. IN SOA     miek.example. miek.example. 3 2 3 4 5"),
				}
				return m
			},
		},
		{
			"dnssec:entbogus",
			func() *dns.Msg { m := dns.NewMsg("bogus.example.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("bogus.example.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("example. IN SOA     miek.example. miek.example. 3 2 3 4 5"),
					dnstest.New("example. IN RRSIG   SOA 16 1 3600 20251008152815 20250910152815 7095 example. 3QyGt6+UNRqST/tex+lDZ4fyrSs5nyyxRBXTho8UTW1S99+koArKyoNMxIOXN2XiBdlsnvvaNa+Af9V1yR9TXsVXqm45lNvFY4lZcVpUXuyO2vgZJSOiZDypOh/hdaNpfPHyt6SMzETSbhpw548caxsA"),
					dnstest.New("example. IN NSEC    sub.*.example. NS SOA MX RRSIG NSEC DNSKEY"),
					dnstest.New("example.        IN RRSIG   NSEC 16 1 5 20251008152815 20250910152815 7095 example. vab6kNsy2t9oJFdAABHGdn/xDqjxKtvyuq1N8QNFXVmRroAcD5J56vQHY8fn2WCuMUlWNdNpYR+ANQOK8z620lGle/PQgoIi5DOz1V2EQ+bzRRmzHft79ZoAO5/xis8gY8XzcWoKGJB1qf8d+PrwTSAA"),
					dnstest.New("c.b.example.    IN NSEC    d.example. A TXT RRSIG NSEC"),
					dnstest.New("c.b.example.    IN RRSIG   NSEC 16 3 5 20251008152815 20250910152815 7095 example. pm+sGFdV8P2NPP0kfLv7hI0iyfhpUdCSu+FeI29P2Bz6TWERJys6z3OTZKeyUP6u+fIjtv8lU5MAStMfRjeM1SxK5qZq/s+h5BVgWn++VyiTuJpvqHiZj12rEMQBf9Nkk4TZbSlYyvqIOv+hg9UtTw8A"),
				}
				return m
			},
		},
		{
			"dnssec:entnogus",
			func() *dns.Msg { m := dns.NewMsg("nogus.example.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("nogus.example.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("example. IN SOA     miek.example. miek.example. 3 2 3 4 5"),
					dnstest.New("example. IN RRSIG   SOA 16 1 3600 20251008152815 20250910152815 7095 example. 3QyGt6+UNRqST/tex+lDZ4fyrSs5nyyxRBXTho8UTW1S99+koArKyoNMxIOXN2XiBdlsnvvaNa+Af9V1yR9TXsVXqm45lNvFY4lZcVpUXuyO2vgZJSOiZDypOh/hdaNpfPHyt6SMzETSbhpw548caxsA"),
					dnstest.New("example. IN NSEC    sub.*.example. NS SOA MX RRSIG NSEC DNSKEY"),
					dnstest.New("example.        IN RRSIG   NSEC 16 1 5 20251008152815 20250910152815 7095 example. vab6kNsy2t9oJFdAABHGdn/xDqjxKtvyuq1N8QNFXVmRroAcD5J56vQHY8fn2WCuMUlWNdNpYR+ANQOK8z620lGle/PQgoIi5DOz1V2EQ+bzRRmzHft79ZoAO5/xis8gY8XzcWoKGJB1qf8d+PrwTSAA"),
					dnstest.New("_ssh._tcp.host2.example. IN NSEC    subdel.example. SRV RRSIG NSEC"),
					dnstest.New("_ssh._tcp.host2.example. IN RRSIG   NSEC 16 4 5 20251008152815 20250910152815 7095 example. XObHcwh4vV7td01x0/Rfnx732Bq8Wn3ot/NckowRN6dRBUSnI1EPNoOWJLPFOSOY/yJMhgUtGcqAJOCugIaIryphRoNbdbxFxOhS0ytlTZsbOdx0/cSfs1ajuLJ9jkxCiEqPMY3E2pcznhJk8oT0ficA"),
				}
				return m
			},
		},
		{
			"dns:wildcardhit",
			func() *dns.Msg { m := dns.NewMsg("blah.blah.d.example.", dns.TypeTXT); return m },
			func() *dns.Msg {
				m := dns.NewMsg("blah.blah.d.example.", dns.TypeTXT)
				m.Answer = []dns.RR{
					dnstest.New(`blah.blah.d.example. IN TXT     "this is a wildcard"`),
				}
				return m
			},
		},
		{
			"dns:wildcardhitnodata",
			func() *dns.Msg { m := dns.NewMsg("blah.blah.d.example.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("blah.blah.d.example.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("example. IN SOA     miek.example. miek.example. 3 2 3 4 5"),
				}
				return m
			},
		},
		{
			"dnssec:wildcardhit",
			func() *dns.Msg { m := dns.NewMsg("blah.blah.d.example.", dns.TypeTXT); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("blah.blah.d.example.", dns.TypeTXT)
				m.Answer = []dns.RR{
					dnstest.New(`blah.blah.d.example. IN TXT     "this is a wildcard"`),
					dnstest.New("blah.blah.d.example. IN RRSIG   TXT 16 2 3600 20251008152815 20250910152815 7095 example. 1gsP+drOy45P9UDN9Kx/4Mz0iSmYRSm34ZRaj8ecCrnIEUgKyzhCUapvV3MFwRJu2H+zSrRcx4cAd5O19+REbbmgna40PsixsLGqePs/1gXtNI9nWZokT102Nj1XbRkthNFvz9AWlboJwwLFrPI+vjsA"),
				}
				m.Ns = []dns.RR{
					dnstest.New("*.d.example. IN NSEC    host1.example. TXT RRSIG NSEC"),
					dnstest.New("*.d.example. IN RRSIG   NSEC 16 2 5 20251008152815 20250910152815 7095 example. /TjeDDQ1T0knqzvuh7cXSWpVbmwkdVDNgVaU4+RwPIKytn1xyWzObvt6IK3AbXeYgp77n3NP9p0AaxxBQgtKP2n2HZtfIr4wX2ITHWwnuZYjbuxwCWP/8S8fA/7fVzClQc+M0t6nhKeSRaTYj1uRny8A"),
				}
				return m
			},
		},
		{
			"dnssec:wildcardhitnodata",
			func() *dns.Msg { m := dns.NewMsg("blah.blah.d.example.", dns.TypeA); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("blah.blah.d.example.", dns.TypeA)
				m.Ns = []dns.RR{
					dnstest.New("*.d.example. IN NSEC    host1.example. TXT RRSIG NSEC"),
					dnstest.New("*.d.example. IN RRSIG   NSEC 16 2 5 20251008152815 20250910152815 7095 example. /TjeDDQ1T0knqzvuh7cXSWpVbmwkdVDNgVaU4+RwPIKytn1xyWzObvt6IK3AbXeYgp77n3NP9p0AaxxBQgtKP2n2HZtfIr4wX2ITHWwnuZYjbuxwCWP/8S8fA/7fVzClQc+M0t6nhKeSRaTYj1uRny8A"),
					dnstest.New("example.     IN SOA     miek.example. miek.example. 3 2 3 4 5"),
					dnstest.New("example.     IN RRSIG   SOA 16 1 3600 20251008152815 20250910152815 7095 example. 3QyGt6+UNRqST/tex+lDZ4fyrSs5nyyxRBXTho8UTW1S99+koArKyoNMxIOXN2XiBdlsnvvaNa+Af9V1yR9TXsVXqm45lNvFY4lZcVpUXuyO2vgZJSOiZDypOh/hdaNpfPHyt6SMzETSbhpw548caxsA"),
				}
				return m
			},
		},
		{
			"dns:hitunderwildcard",
			func() *dns.Msg { m := dns.NewMsg("c.b.example.", dns.TypeTXT); return m },
			func() *dns.Msg {
				m := dns.NewMsg("c.b.example.", dns.TypeTXT)
				m.Answer = []dns.RR{
					dnstest.New(`c.b.example. IN TXT     "do I see this"`),
				}
				return m
			},
		},
		{
			"dnssec:hitunderwildcard",
			func() *dns.Msg { m := dns.NewMsg("c.b.example.", dns.TypeTXT); m.Security = true; return m },
			func() *dns.Msg {
				m := dns.NewMsg("c.b.example.", dns.TypeTXT)
				m.Answer = []dns.RR{
					dnstest.New(`c.b.example. IN TXT     "do I see this"`),
					dnstest.New("c.b.example. IN RRSIG   TXT 16 3 3600 20251008152815 20250910152815 7095 example. t0bE9+GNX9DK9No0AZ6dYOjCb2ZZ4VGJHAfFVa6Lf8R2Wo0z0O5hHmGQ 7v4JDoNQqy1nvYXXhjsAU4VqYMW0ZNA6aiMxe6B1zTtunfdc01SBw7z0 MwvXk6C8fmn7WaC4mTXz9FQT5W/MUZcYYtLXTDwA"),
				}
				return m
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			expmsg := tc.exp()
			exprrs := []dns.RR{}
			for rr := range expmsg.RRs() {
				exprrs = append(exprrs, rr)
			}

			rmsg := dnszone.Retrieve(z, tc.in(), nil)
			gotrrs := []dns.RR{}
			for rr := range rmsg.RRs() {
				gotrrs = append(gotrrs, rr)
			}
			if len(exprrs) != len(gotrrs) {
				t.Errorf("expected %d RRs, got %d", len(exprrs), len(gotrrs))
				t.Logf("%s", rmsg)
			}
			for i := range gotrrs {
				if !dns.Equal(gotrrs[i], exprrs[i]) {
					t.Logf("%s", rmsg)
					t.Fatalf("expected %s and\n\t%s to be equal", gotrrs[i], exprrs[i])
				}
			}
		})
	}
}

func TestZoneEdgeCases(t *testing.T) {
	z := New("miek.nl.", "testdata/db.miek.nl")
	if err := z.Load(); err != nil {
		t.Fatal(err)
	}
	testcases := []struct {
		name string
		in   func() *dns.Msg
		exp  func() *dns.Msg
	}{
		{
			"cname",
			func() *dns.Msg { m := dns.NewMsg("mmark.miek.nl.", dns.TypeA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("mmark.miek.nl.", dns.TypeA)
				m.Rcode = dns.RcodeNameError
				m.Ns = []dns.RR{
					dnstest.New("miek.nl. IN SOA     miek.miek.nl. miek.miek.nl. 5 1 1 1 1"),
				}
				return m
			},
		},
		{
			"apexcname",
			func() *dns.Msg { m := dns.NewMsg("apex.miek.nl.", dns.TypeSOA); return m },
			func() *dns.Msg {
				m := dns.NewMsg("apex.miek.nl.", dns.TypeSOA)
				m.Answer = []dns.RR{
					dnstest.New("apex.miek.nl. IN CNAME   miek.nl."),
					dnstest.New("miek.nl. IN SOA     miek.miek.nl. miek.miek.nl. 5 1 1 1 1"),
				}
				return m
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			expmsg := tc.exp()
			exprrs := []dns.RR{}
			for rr := range expmsg.RRs() {
				exprrs = append(exprrs, rr)
			}

			rmsg := dnszone.Retrieve(z, tc.in(), nil)
			gotrrs := []dns.RR{}
			for rr := range rmsg.RRs() {
				gotrrs = append(gotrrs, rr)
			}
			if len(exprrs) != len(gotrrs) {
				t.Errorf("expected %d RRs, got %d", len(exprrs), len(gotrrs))
				t.Logf("%s", rmsg)
			}
			for i := range gotrrs {
				if !dns.Equal(gotrrs[i], exprrs[i]) {
					t.Logf("%s", rmsg)
					t.Fatalf("expected %s and\n\t%s to be equal", gotrrs[i], exprrs[i])
				}
			}
		})
	}
}
