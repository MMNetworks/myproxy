package drunk

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

type Drunk struct {
	i        uint64 // counter of queries
	drop     uint64
	delay    uint64
	truncate uint64

	duration time.Duration
}

func (d *Drunk) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		i := atomic.LoadUint64(&d.i)
		atomic.AddUint64(&d.i, 1)

		drop := d.drop > 0 && i%d.drop == 0
		delay := d.delay > 0 && i%d.delay == 0
		trunc := d.truncate > 0 && i%d.truncate == 0

		m := r.Copy()
		dnsutil.SetReply(m, r)
		m.Authoritative = true
		m.Truncated = trunc

		rw := dnstest.NewRecorder(w)
		next.ServeDNS(ctx, rw, r)

		if drop || rw.Msg == nil { // drop or hijacked conn
			log().With(dnsctx.Id(ctx)).Debug("Dropping")
			return
		}
		if delay {
			log().With(dnsctx.Id(ctx)).Debug("Delaying", slog.Duration("delay", d.duration))
			time.Sleep(d.duration)
		}
		if trunc {
			rw.Msg.Truncated = true
			// have to repack now
			if err := rw.Msg.Pack(); err != nil {
				dnslog.PackFail(ctx, log(), Err(err))
			}
		}

		io.Copy(w, rw.Msg)
	})
}
