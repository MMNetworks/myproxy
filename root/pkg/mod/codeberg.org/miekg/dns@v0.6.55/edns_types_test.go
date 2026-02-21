package dns_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// This shows how to add an EDE option.
func ExampleEDE() {
	// This is a dns.HandlerFunc for use in a dns.Server.
	_ = func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := r.Copy()
		dnsutil.SetReply(m, r)

		ede := &dns.EDE{InfoCode: dns.ExtendedErrorCensored}
		m.Pseudo = append(m.Pseudo, ede)

		if err := m.Pack(); err != nil {
			log.Println(err)
			return
		}
		io.Copy(w, m)
	}
}

// This shows how to add an NSID option.
func ExampleNSID() {
	// This is a dns.HandlerFunc for use in a dns.Server.
	_ = func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := r.Copy()
		dnsutil.SetReply(m, r)

		nsid := &dns.NSID{Nsid: hex.EncodeToString([]byte("its_me!"))}
		m.Pseudo = append(m.Pseudo, nsid)

		if err := m.Pack(); err != nil {
			log.Println(err)
			return
		}
		io.Copy(w, m)
	}
}

// This shows how to add a PADDING option.
func ExamplePADDING() {
	// This is a dns.HandlerFunc for use in a dns.Server.
	_ = func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := r.Copy()
		dnsutil.SetReply(m, r)

		padding := &dns.PADDING{Padding: hex.EncodeToString(bytes.Repeat([]byte{0}, 20))}
		m.Pseudo = append(m.Pseudo, padding)

		if err := m.Pack(); err != nil {
			log.Println(err)
			return
		}
		io.Copy(w, m)
	}
}
