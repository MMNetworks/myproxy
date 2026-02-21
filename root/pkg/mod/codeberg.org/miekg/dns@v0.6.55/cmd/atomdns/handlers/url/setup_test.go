package url

import (
	"slices"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Url
	}{
		{`url path {
				https://example.org
				https://example.net
			}
			}`, &Url{Path: "path", URLs: []string{"https://example.org", "https://example.net"}}},
	}
	for i, tc := range testcases {
		url := new(Url)
		co := dnsserver.NewTestController(tc.input)
		err := url.Setup(co)
		if err != nil {
			t.Error(err)
			continue
		}

		if slices.Compare(tc.exp.URLs, url.URLs) != 0 {
			t.Errorf("test %d: expected %v, got %v", i, tc.exp.URLs, url.URLs)
		}
	}
}
