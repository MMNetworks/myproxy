package metrics

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsmetrics"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Metrics struct {
	disable bool

	i uint64
	N uint64
}

func (m *Metrics) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if m.disable || m.N == 0 {
			next.ServeDNS(ctx, w, r)
			return
		}
		if !dnsmetrics.Should(&m.i, m.N) {
			next.ServeDNS(ctx, w, r)
			return
		}

		net := dnsutil.Network(w)
		fam := strconv.Itoa(dnsutil.Family(w))
		flags := bufPool.Get().(*bytes.Buffer)
		if r.Security {
			flags.WriteString(" do")
		}
		if r.CompactAnswers {
			flags.WriteString(" co")
		}
		if r.Delegation {
			flags.WriteString(" de")
		}
		if r.AuthenticatedData {
			flags.WriteString(" ad")
		}
		if r.CheckingDisabled {
			flags.WriteString(" cd")
		}
		if flags.Len() > 1 {
			Requests.WithLabelValues(dns.Zone(ctx), net, fam, string(flags.Bytes()[1:])).Inc()
		} else {
			Requests.WithLabelValues(dns.Zone(ctx), net, fam, "").Inc()
		}
		flags.Reset()
		bufPool.Put(flags)

		RequestSize.WithLabelValues(dns.Zone(ctx), net, fam).Observe(float64(len(r.Data)))

		rw := dnstest.NewRecorder(w)
		next.ServeDNS(ctx, rw, r)

		// if being hijacked, we don't have anything here, we check for that by checking if we actually have a
		// message written to us.
		if rw.Msg == nil {
			return
		}

		rw.Msg.Options = dns.MsgOptionUnpackHeader // we only need to rcode
		rw.Msg.Unpack()
		RequestDuration.WithLabelValues(dns.Zone(ctx), net, fam).Observe(time.Since(rw.Start).Seconds())
		ResponseSize.WithLabelValues(dns.Zone(ctx), net, fam).Observe(float64(len(rw.Msg.Data)))
		Responses.WithLabelValues(dns.Zone(ctx), net, fam, dnsutil.RcodeToString(rw.Msg.Rcode)).Inc()

		io.Copy(w, rw.Msg)
	})
}

var bufPool = &sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

var (
	Dropped = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: subsystem,
		Name: "dropped_total",
		Help: "Counter of dropped requests. These are reported via the server's MsgInvalidFunc.",
	})

	Requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: subsystem,
		Name: "requests_total",
		Help: "Counter of requests made per zone, network and family.",
	}, []string{"zone", "network", "family", "flags"})

	Responses = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace, Subsystem: subsystem,
		Name: "responses_total",
		Help: "Counter of responses and response codes.",
	}, []string{"zone", "network", "family", "rcode"})

	RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace, Subsystem: subsystem,
		Name:    "request_duration_seconds",
		Buckets: prometheus.ExponentialBuckets(0.00025, 2, 16), // from 0.25ms to 8 seconds
		Help:    "Histogram of the time (in seconds) each request took per zone.",
	}, []string{"zone", "network", "family"})

	RequestSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace, Subsystem: subsystem,
		Name:    "request_size_bytes",
		Help:    "Size of the requests.",
		Buckets: []float64{0, 100, 200, 300, 400, 511, 1023, 2047, 4095, 8291, 16e3, 32e3, 48e3, 64e3},
	}, []string{"zone", "network", "family"})

	ResponseSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace, Subsystem: subsystem,
		Name:    "response_size_bytes",
		Help:    "Size of the returned response in bytes.",
		Buckets: []float64{0, 100, 200, 300, 400, 511, 1023, 2047, 4095, 8291, 16e3, 32e3, 48e3, 64e3},
	}, []string{"zone", "network", "family"})
)

const (
	subsystem = "dns"
	Namespace = "atomdns"
)
