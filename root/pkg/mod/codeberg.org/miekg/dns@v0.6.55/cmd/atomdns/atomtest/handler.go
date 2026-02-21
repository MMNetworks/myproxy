package atomtest

import (
	"context"
	"io"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnsutil"
)

// Echo is a [dns.HandlerFunc] that echos the message m. Any dnsctx.Funcs set in the context are run.
var Echo = dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, r)
	m = dnsctx.Funcs(ctx, m)
	if err := m.Pack(); err != nil {
		return
	}
	io.Copy(w, m)
})

// Noop is a [dns.HandlerFunc] that does nothing.
var Noop = dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {})
