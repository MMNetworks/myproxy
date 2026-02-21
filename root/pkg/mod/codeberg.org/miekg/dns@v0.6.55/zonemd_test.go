package dns_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"sort"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
)

func TestZONEMD(t *testing.T) {
	var testcases = []struct {
		name   string
		zone   string
		zonemd *dns.ZONEMD
	}{
		{
			name: "simple-example-rfc8976",
			zone: `
example.      86400  IN  SOA     ns1 admin 2018031900 1800 900 604800 86400
              86400  IN  NS      ns1
              86400  IN  NS      ns2
              86400  IN  ZONEMD  2018031900 1 1 c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c
ns1           3600   IN  A       203.0.113.63
ns2           3600   IN  AAAA    2001:db8::63
`,
			zonemd: dnstest.New(`example. 3600 IN ZONEMD 2018031900 1 1 C68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c`).(*dns.ZONEMD),
		},

		{
			name:   "root-servers-rfc8976",
			zone:   func() string { buf, _ := os.ReadFile("testdata/root-servers.net"); return string(buf) }(),
			zonemd: dnstest.New(`root-servers.net. 3600000 IN  ZONEMD  2018091100 1 1 f1ca0ccd91bd5573d9f431c00ee0101b2545c97602be0a97 8a3b11dbfc1c776d5b3e86ae3d973d6b5349ba7f04340f79`).(*dns.ZONEMD),
		},
		{
			name:   "root.zone",
			zone:   func() string { buf, _ := os.ReadFile("testdata/root.zone"); return string(buf) }(),
			zonemd: dnstest.New(`. 86400 IN ZONEMD 2025110400 1 1 f13768ece75d92db1c998f3d0f209e91ae42b3517a244fd577c488e42a81423b9f952fb31ff78222cd9d0dd067b8d512`).(*dns.ZONEMD),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			zone := []dns.RR{}
			z := dns.NewZoneParser(strings.NewReader(tc.zone), "example.", "<test>")
			for rr, ok := z.Next(); ok; rr, ok = z.Next() {
				zone = append(zone, rr)
			}
			zonemd := dns.NewZONEMD("example.", dns.ZONEMDSchemeSimple, dns.ZONEMDHashSHA384)
			sort.Sort(dns.RRset(zone))
			err := zonemd.Sign(zone, &dns.ZONEMDOption{})
			if err != nil {
				t.Fatal(err)
			}

			digest, _ := hex.DecodeString(zonemd.Digest)
			tcdigest, _ := hex.DecodeString(tc.zonemd.Digest)
			if !bytes.Equal(digest, tcdigest) {
				t.Fatalf("expected digest %q, got %q", tc.zonemd.Digest, zonemd.Digest)
			}
		})
	}
}
