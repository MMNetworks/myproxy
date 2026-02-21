package cookie

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   string
	}{
		{`cookie`, ""},
		{`cookie "geheim"`, "geheim"},
	}
	for i, tc := range testcases {
		cookie := new(Cookie)
		co := dnsserver.NewTestController(tc.input)
		err := cookie.Setup(co)

		if tc.exp == "" {
			if err == nil {
				t.Errorf("test %d: expected error, got nothing", i)
			}
			continue
		}

		if tc.exp != cookie.Secret {
			t.Errorf("test %d: expected %s, got %s", i, tc.input, cookie.Secret)
		}
	}
}
