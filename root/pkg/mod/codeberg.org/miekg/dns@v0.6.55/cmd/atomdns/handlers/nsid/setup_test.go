package nsid

import (
	"encoding/hex"
	"os"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	def, err := os.Hostname()
	if err != nil {
		def = "localhost"
	}
	testcases := []struct {
		input string
		exp   string
	}{
		{`nsid`, hex.EncodeToString([]byte(def))},
		{`nsid "ps0"`, hex.EncodeToString([]byte("ps0"))},
	}
	for i, tc := range testcases {
		nsid := new(Nsid)
		co := dnsserver.NewTestController(tc.input)
		err := nsid.Setup(co)

		if tc.exp == "" {
			if err == nil {
				t.Errorf("test %d: expected error, got nothing", i)
			}
			continue
		}

		if tc.exp != nsid.Data {
			t.Errorf("test %d: expected %s, got %s", i, tc.input, nsid.Data)
		}
	}
}
