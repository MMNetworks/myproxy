package dnstest

import "codeberg.org/miekg/dns"

// NewMsg returns a test message with an ID of 3, the question set to"www.example.org./A. The message is
// packed before it is returned.
func NewMsg() *dns.Msg {
	m := dns.NewMsg("www.example.org.", dns.TypeA)
	m.ID = 3
	m.Pack()
	return m
}
