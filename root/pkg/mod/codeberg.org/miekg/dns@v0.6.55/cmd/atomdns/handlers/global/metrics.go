package global

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HealthDuration is the metric used for exporting how fast we can retrieve the /health endpoint.
	HealthDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace:                   Namespace,
		Subsystem:                   subsystem,
		Name:                        "request_duration_seconds",
		Buckets:                     prometheus.ExponentialBuckets(0.00025, 10, 5), // from 0.25ms to 2.5 seconds
		NativeHistogramBucketFactor: 1.05,
		Help:                        "Histogram of the time (in seconds) each request took.",
	})
	// HealthFailures is the metric used to count how many times the health request failed
	HealthFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Subsystem: subsystem,
		Name:      "request_failures_total",
		Help:      "The number of times the health check failed.",
	})
)

const (
	subsystem = "health"
	Namespace = "atomdns"
)
