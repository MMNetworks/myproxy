package dnshttp

import (
	"net/http"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func TestDOH(t *testing.T) {
	testcases := map[string]struct {
		method string
		url    string
	}{
		"POST request HTTPS":       {method: http.MethodPost, url: "https://example.org:443"},
		"POST request HTTP":        {method: http.MethodPost, url: "http://example.org:443"},
		"POST request no protocol": {method: http.MethodPost, url: "example.org:443"},
		"GET request HTTPS":        {method: http.MethodGet, url: "https://example.org:443"},
		"GET request HTTP":         {method: http.MethodGet, url: "http://example.org"},
		"GET request no protocol":  {method: http.MethodGet, url: "example.org:443"},
	}

	MsgAcceptFunc = func(m *dns.Msg) dns.MsgAcceptAction { return dns.MsgAccept }

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			m := new(dns.Msg)
			dnsutil.SetQuestion(m, "example.org.", dns.TypeDNSKEY)

			req, err := NewRequest(tc.method, tc.url, m)
			if err != nil {
				t.Fatalf("failure to make request: %s", err)
			}

			m1, err := Request(req)
			if err != nil {
				t.Fatalf("failure to get message from request: %s", err)
			}

			if x := m1.Question[0].Header().Name; x != "example.org." {
				t.Errorf("qname expected %s, got %s", "example.org.", x)
			}
			if x, ok := m1.Question[0].(*dns.DNSKEY); !ok {
				t.Errorf("qtype expected %T, got %T", &dns.DNSKEY{}, x)
			}
		})
	}
}
