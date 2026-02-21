package dnsutil

import (
	"strings"
	"testing"
	"unicode"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
)

func TestStringToMsg(t *testing.T) {
	testcases := []struct {
		in  func() *dns.Msg
		exp string
	}{
		{
			in: func() *dns.Msg {
				m := dns.NewMsg("miek.nl.", dns.TypeMX)
				m.ID = 49123
				m.Response, m.RecursionDesired, m.RecursionAvailable = true, true, true
				m.Answer = []dns.RR{
					dnstest.New("miek.nl. 11381 IN MX 10 aspmx2.googlemail.com."),
					dnstest.New("miek.nl. 11381 IN MX 1 aspmx.l.google.com."),
				}
				return m
			},
			exp: `
;; QUERY, rcode: NOERROR, id: 49123, flags: qr rd ra
;; QUESTION: 1, PSEUDO: 0, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0, DATA SIZE: 0

;; QUESTION SECTION:
miek.nl.                IN      MX

;; ANSWER SECTION:
miek.nl.        11381   IN      MX      10 aspmx2.googlemail.com.
miek.nl.        11381   IN      MX      1 aspmx.l.google.com.
`,
		},
		{
			in: func() *dns.Msg {
				m := dns.NewMsg("miek.nl.", dns.TypeMX)
				m.ID = 49123
				m.Response, m.RecursionDesired, m.RecursionAvailable = true, true, true
				m.Rcode = dns.RcodeNameError
				return m
			},
			exp: `
;; QUERY, rcode: NXDOMAIN, id: 49123, flags: qr rd ra
;; QUESTION: 1, PSEUDO: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0, DATA SIZE: 0

;; QUESTION SECTION:
miek.nl.                IN      MX
`,
		},
	}
	for i, tc := range testcases {
		s := tc.in().String()
		m, err := StringToMsg(s)
		if err != nil {
			t.Error(err)
		}
		if trim(m.String()) != trim(tc.exp) {
			t.Logf("%s\n%s", m.String(), tc.exp)
			t.Errorf("test %d, string representations do not match", i)
		}
	}
}

func trim(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}
