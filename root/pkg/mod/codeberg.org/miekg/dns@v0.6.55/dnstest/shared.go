package dnstest

import (
	"io"

	"codeberg.org/miekg/dns"
)

// This is copied to zdnstest.go in the main package to also have access to these functions and not have an
// import cycle. See dnstest_generate.go.

// New calls [dns.New], but panics if an error is returned.
func New(s string) dns.RR {
	rr, err := dns.New(s)
	if err != nil {
		panic("dnstest: " + err.Error())
	}
	return rr
}

// Read calls [dns.Read], but panics if an error is returned.
func Read(r io.Reader) dns.RR {
	rr, err := dns.Read(r)
	if err != nil {
		panic("dnstest: " + err.Error())
	}
	return rr
}
