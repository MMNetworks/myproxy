package dns

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"

	"codeberg.org/miekg/dns/rdata"
)

func TestDNSSECSignVerify(t *testing.T) {
	// Add wildcard, sorting of RRs. etc.
	testcases := []struct {
		name      string
		algorithm uint8
		bitsize   int
		rrs       []RR
	}{
		{
			"rsasha256", RSASHA256, 1024,
			[]RR{
				&SRV{Hdr: Header{Name: "srv.miek.nl.", Class: ClassINET, TTL: 600}, SRV: rdata.SRV{Port: 1000, Weight: 80, Target: "web1.miek.nl."}},
			},
		},
		{
			"ecdsap256sha256", ECDSAP256SHA256, 256,
			[]RR{
				&SRV{Hdr: Header{Name: "srv.miek.nl.", Class: ClassINET, TTL: 600}, SRV: rdata.SRV{Port: 1000, Weight: 80, Target: "web1.miek.nl."}},
			},
		},
		{
			"ed25519", ED25519, 256,
			[]RR{
				&SRV{Hdr: Header{Name: "srv.miek.nl.", Class: ClassINET, TTL: 600}, SRV: rdata.SRV{Port: 1000, Weight: 80, Target: "web1.miek.nl."}},
			},
		},
		{
			"rsasha256-sorting", RSASHA256, 1024,
			[]RR{
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, NS: rdata.NS{Ns: "linode.atoom.net."}},
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, NS: rdata.NS{Ns: "ns-ext.nlnetlabs.nl."}},
				&NS{Hdr: Header{Name: "miek.nl.", Class: ClassINET, TTL: 600}, NS: rdata.NS{Ns: "omval.tednet.nl"}},
			},
		},
	}

	options := &SignOption{}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error

			key := NewDNSKEY("miek.nl.", tc.algorithm)
			priv, _ := key.Generate(tc.bitsize)

			sig := NewRRSIG("miek.nl.", tc.algorithm, key.KeyTag())
			switch tc.algorithm {
			case RSASHA256:
				err = sig.Sign(priv.(*rsa.PrivateKey), tc.rrs, options)
			case ECDSAP256SHA256:
				err = sig.Sign(priv.(*ecdsa.PrivateKey), tc.rrs, options)
			case ED25519:
				err = sig.Sign(priv.(ed25519.PrivateKey), tc.rrs, options)
			}
			if err != nil {
				t.Fatalf("failure to sign: %s", err)
			}

			err = sig.Verify(key, tc.rrs, options)
			if err != nil {
				t.Fatalf("failure to verify: %s", err)
			}
		})
	}
}

func TestDNSSECKeyTag(t *testing.T) {
	testcases := []struct {
		tag uint16
		rr  RR
	}{
		{
			27461, dnstestNew("test.  IN DNSKEY  257 3 1 AwEAAcntNdoMnY8pvyPcpDTAaiqHyAhf53XUBANq166won/fjBFvmuzhTuP5r4el/pV0tzEBL73zpoU48BqF66uiL+qRijXCySJiaBUvLNll5rpwuduAOoVpmwOmkC4fV6izHOAx/Uy8c+pYP0YR8+1P7GuTFxgnMmt9sUGtoe+la0X/"),
		},
		{
			27461, dnstestNew("test.  IN DNSKEY  257 3 1 AwEAAf0bKO/m45ylk5BlSLmQHQRBLx1m/ZUXvyPFB387bJXxnTk6so3ub97L1RQ+8bOoiRh3Qm5EaYihjco7J8b/W5WbS3tVsE79nY584RfTKT2zcZ9AoFP2XLChXxPIf/6l0H9n6sH0aBjsG8vabEIp8e06INM3CXVPiMRPPeGNa0Ub"),
		},
		{
			10771, dnstestNew("example.net. 3600 IN DNSKEY 257 3 14 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40"),
		},
	}
	for i, tc := range testcases {
		got := tc.rr.(*DNSKEY).KeyTag()
		if got != tc.tag {
			t.Errorf("test %d, expected %d, got %d", i, tc.tag, got)
		}
	}
}

func TestDNSSECVerify(t *testing.T) {
	testcases := []struct {
		name string
		key  *DNSKEY
		sig  *RRSIG
		rrs  []RR
	}{
		{
			"root",
			&DNSKEY{
				Hdr: Header{Name: ".", Class: ClassINET, TTL: 172800}, DNSKEY: rdata.DNSKEY{Flags: 256, Protocol: 3, Algorithm: RSASHA256,
					PublicKey: "AwEAAbauxLSFZ+KSWi2cT6TJbm3d+GIVqb2N1XnDjMsRme0b6JlGp/cvwmM5CaJ5LQ7tG1r7LuTHjYZadtbNk2nZmclq9r4KInS48ungoAZb0gJXVw8IvBTBb1YWQmiBqD285pJuORwTii7DF++nNJJk3i55HJt9SmBI7m7t8nvx7OOY/w0inxg3fLH2uY0SKO8he4FGwMc4Ubiab8N8Yhyhh+FkKKdD/+oAcuGF75PjlSXO460B4MlNLlEcjDEzIsKauRYx4YVgSaNomGhMMFblmXRzgW+1R6ywvm5mC9+omlyyizZp2GJfPwGMezuKSGDndO6CYYEc5/lsRhvBYsGjdPM=",
				},
			},
			&RRSIG{
				Hdr: Header{Name: ".", Class: ClassINET, TTL: 86400}, RRSIG: rdata.RRSIG{TypeCovered: TypeSOA, Algorithm: RSASHA256, Expiration: 1760245200, Inception: 1759118400, OrigTTL: 86400, KeyTag: 46441, SignerName: ".",
					Signature: "Bi335z6iBqX1BsA6AUc29BdgoVcn2a6hfoowvC0OqNbQ1XdIz6lJ6L7iXPBYwUXTP85yII2wIBhIQJSKKuBnGmYwgXsRR7d6vxbcC63UKp6lG/xjMzae2TvuQINQhMCE2N+ufN4DCmlZspdDmWOyPkemJhncrWA+V6GGWLbCtVXPEbcgAvaNyVtFlLp788SdoDy1rpvIM2ZI9tGM2gxZG7wMLPIODtdl865H87kHaHbBkfKkCHsVCeWANoW9r8usdgt8+2HHf3w67HTERUv2NN31fgdkezaS1/7LMaMUb+5mqLygIJPVXbmK8wiUbnyuYW6Ems+R1FEnc2Dd5x5kAw==",
				},
			},
			[]RR{&SOA{Hdr: Header{Name: ".", Class: ClassINET, TTL: 86400}, SOA: rdata.SOA{Ns: "a.root-servers.net.", Mbox: "nstld.verisign-grs.com.", Serial: 2025092900, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: 86400}}},
		},
		{
			"org",
			&DNSKEY{
				Hdr: Header{Name: "org.", Class: ClassINET, TTL: 3600}, DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: RSASHA256,
					PublicKey: "AwEAAexZJ/1wfyNCxNPrTZizaG7UlibGhP+AyogR6bqjptKweEgE4gD8GxRQJkt+Fn5pCoNqzmm1ZnEoKqvm93uOYtbKkYQDGH+W69J66MSKpgIyS+mT/4iaXn+lpb5o99l/sf7lHMa975O/fqN6aPUll4hUbN2T1LHv6HzQuQCtNRJA8jHGwX5q0NMmh2Z+yaG6B9cISerje9l5L+ID2ydJ6zXquYteoIUvX2xzqnXCdHPSvD+oL6R/weW+tztdFS1hok/1z3tn5NzmcaOLll9nXniCozEpLFEGPswyvtphWgCYhI8bBTqhUsIwfIwLSBQTEg2oCX7sS5CbXg44OqwhIW8=",
				},
			},
			&RRSIG{
				Hdr: Header{Name: "org.", Class: ClassINET, TTL: 3600}, RRSIG: rdata.RRSIG{TypeCovered: TypeDNSKEY, Algorithm: RSASHA256, Labels: 1, Expiration: 1770478705, Inception: 1768660705, OrigTTL: 3600, KeyTag: 26974, SignerName: "org.",
					Signature: "YFVPRIIx6ZItt/17yrZmtnBQOFRD44rNDwOh3BQC+NhaM7+6w5kVVpMbVMFy6X8yuXp3+A857I6g6FYVB2p7zDRhq1hkIRyxyYKMmyQmgd0d/Km+vYU+KQjSDWFp0Cm7B+3q5bvbZKRsWho36fofO37jyWkDKYl3tPm8hSCzNuCJ7NfH+3GpcztYL/M3xeHJSJ1wwzFZUW7ioAY4cnmdzHEraXi1O/2UKb+h0lR6CdvNGSe6FLsmx1OETQ8JKneopXpm3RG07AwMSMXw+lgo1d0DZiXwscJpcqHWm9eWaI7OQX6JFl96Yjnjjh1z8gLXFYMXDxLUB3wBtYF903ukiQ==",
				},
			},
			[]RR{
				&DNSKEY{
					Hdr: Header{Name: "org.", Class: ClassINET, TTL: 3600}, DNSKEY: rdata.DNSKEY{Flags: 256, Protocol: 3, Algorithm: RSASHA256,
						PublicKey: "AwEAAfCN1yguCELJYujNmis5cjZFEW4UcxwSitTh7m1RYMEHTjhSCCzeMZ+UrpNIxLDLwAtWCcAQPoLuQdbhbMBo17pkK2UF26k+WKLN4Ieyw8SsAFScQkf+K7wCYJ4fRJgpsvZgRYBwzpsfQjm26Jd8B7olV02AnvxUHuPo1QeGz0Dd",
					},
				},
				&DNSKEY{
					Hdr: Header{Name: "org.", Class: ClassINET, TTL: 3600}, DNSKEY: rdata.DNSKEY{Flags: 256, Protocol: 3, Algorithm: RSASHA256,
						PublicKey: "AwEAAa0ig3MNvgtoYj85frPVdYmRm98PlHMHxQBQRRsGC4wucf5PHv9wlSQOJUfGXY45KlJpdgZX8B6s4vHZwOGW2utqp9u2JLMFaMb5bhZUlbD/qufIQu8hcLtoTkORdaK0lo+9vx8R+N2I0DcIVVWBjtSoNjb5L/ssPPicUsBobl2B",
					},
				},
				&DNSKEY{
					Hdr: Header{Name: "org.", Class: ClassINET, TTL: 3600}, DNSKEY: rdata.DNSKEY{Flags: 257, Protocol: 3, Algorithm: RSASHA256,
						PublicKey: "AwEAAexZJ/1wfyNCxNPrTZizaG7UlibGhP+AyogR6bqjptKweEgE4gD8GxRQJkt+Fn5pCoNqzmm1ZnEoKqvm93uOYtbKkYQDGH+W69J66MSKpgIyS+mT/4iaXn+lpb5o99l/sf7lHMa975O/fqN6aPUll4hUbN2T1LHv6HzQuQCtNRJA8jHGwX5q0NMmh2Z+yaG6B9cISerje9l5L+ID2ydJ6zXquYteoIUvX2xzqnXCdHPSvD+oL6R/weW+tztdFS1hok/1z3tn5NzmcaOLll9nXniCozEpLFEGPswyvtphWgCYhI8bBTqhUsIwfIwLSBQTEg2oCX7sS5CbXg44OqwhIW8=",
					},
				},
			},
		},
		{
			"org-from-string",
			dnstestNew("org.	30	IN	DNSKEY	257 3 8 AwEAAexZJ/1wfyNCxNPrTZizaG7UlibGhP+AyogR6bqjptKweEgE4gD8GxRQJkt+Fn5pCoNqzmm1ZnEoKqvm93uOYtbKkYQDGH+W69J66MSKpgIyS+mT/4iaXn+lpb5o99l/sf7lHMa975O/fqN6aPUll4hUbN2T1LHv6HzQuQCtNRJA8jHGwX5q0NMmh2Z+yaG6B9cISerje9l5L+ID2ydJ6zXquYteoIUvX2xzqnXCdHPSvD+oL6R/weW+tztdFS1hok/1z3tn5NzmcaOLll9nXniCozEpLFEGPswyvtphWgCYhI8bBTqhUsIwfIwLSBQTEg2oCX7sS5CbXg44OqwhIW8=").(*DNSKEY),
			dnstestNew("org.	30	IN	RRSIG	DNSKEY 8 1 3600 20260207153825 20260117143825 26974 org. YFVPRIIx6ZItt/17yrZmtnBQOFRD44rNDwOh3BQC+NhaM7+6w5kVVpMbVMFy6X8yuXp3+A857I6g6FYVB2p7zDRhq1hkIRyxyYKMmyQmgd0d/Km+vYU+KQjSDWFp0Cm7B+3q5bvbZKRsWho36fofO37jyWkDKYl3tPm8hSCzNuCJ7NfH+3GpcztYL/M3xeHJSJ1wwzFZUW7ioAY4cnmdzHEraXi1O/2UKb+h0lR6CdvNGSe6FLsmx1OETQ8JKneopXpm3RG07AwMSMXw+lgo1d0DZiXwscJpcqHWm9eWaI7OQX6JFl96Yjnjjh1z8gLXFYMXDxLUB3wBtYF903ukiQ==").(*RRSIG),
			[]RR{
				dnstestNew("org.	30	IN	DNSKEY	256 3 8 AwEAAfCN1yguCELJYujNmis5cjZFEW4UcxwSitTh7m1RYMEHTjhSCCzeMZ+UrpNIxLDLwAtWCcAQPoLuQdbhbMBo17pkK2UF26k+WKLN4Ieyw8SsAFScQkf+K7wCYJ4fRJgpsvZgRYBwzpsfQjm26Jd8B7olV02AnvxUHuPo1QeGz0Dd"),
				dnstestNew("org.	30	IN	DNSKEY	256 3 8 AwEAAa0ig3MNvgtoYj85frPVdYmRm98PlHMHxQBQRRsGC4wucf5PHv9wlSQOJUfGXY45KlJpdgZX8B6s4vHZwOGW2utqp9u2JLMFaMb5bhZUlbD/qufIQu8hcLtoTkORdaK0lo+9vx8R+N2I0DcIVVWBjtSoNjb5L/ssPPicUsBobl2B"),
				dnstestNew("org.	30	IN	DNSKEY	257 3 8 AwEAAexZJ/1wfyNCxNPrTZizaG7UlibGhP+AyogR6bqjptKweEgE4gD8GxRQJkt+Fn5pCoNqzmm1ZnEoKqvm93uOYtbKkYQDGH+W69J66MSKpgIyS+mT/4iaXn+lpb5o99l/sf7lHMa975O/fqN6aPUll4hUbN2T1LHv6HzQuQCtNRJA8jHGwX5q0NMmh2Z+yaG6B9cISerje9l5L+ID2ydJ6zXquYteoIUvX2xzqnXCdHPSvD+oL6R/weW+tztdFS1hok/1z3tn5NzmcaOLll9nXniCozEpLFEGPswyvtphWgCYhI8bBTqhUsIwfIwLSBQTEg2oCX7sS5CbXg44OqwhIW8="),
			},
		},
	}

	options := &SignOption{}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sig.Verify(tc.key, tc.rrs, options)
			if err != nil {
				t.Fatalf("failure to verify: %s", err)
			}
		})
	}
}
