package sign

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Duration is the metric used for exporting how fast we can sign each zone..
	Duration = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: (&Sign{}).Key(),
		Name:      "duration_seconds",
		Help:      "Time (in seconds) each zone signing took.",
	}, []string{"zone"})
	// Expire is the metric used to track the signature expire.
	Expire = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: (&Sign{}).Key(),
		Name:      "rrsig_expire_timestamp",
		Help:      "The zone's signature expire in unix epoch.",
	}, []string{"zone"})
)

const (
	Namespace = "atomdns"
)
