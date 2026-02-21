package acl

import (
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestsBlock = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace, Subsystem: subsystem,
		Name: "blocked_requests_total",
		Help: "Counter of DNS requests being blocked.",
	}, []string{"zone", "network", "family"})

	RequestsFilter = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace, Subsystem: subsystem,
		Name: "filtered_requests_total",
		Help: "Counter of DNS requests being filtered.",
	}, []string{"zone", "network", "family"})

	RequestsAllow = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace, Subsystem: subsystem,
		Name: "allowed_requests_total",
		Help: "Counter of DNS requests being allowed.",
	}, []string{"zone", "network", "family"})

	RequestsDrop = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: metrics.Namespace, Subsystem: subsystem,
		Name: "dropped_requests_total",
		Help: "Counter of DNS requests being dropped.",
	}, []string{"zone", "network", "family"})
)

const subsystem = "acl"
