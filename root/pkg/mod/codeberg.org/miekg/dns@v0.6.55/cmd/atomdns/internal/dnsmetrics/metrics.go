package dnsmetrics

// Should returns true when we should gather a metric. This is done every N times. If N isn't 0 (no metrics),
// i is incremented.
func Should(i *uint64, N uint64) bool {
	if N == 0 {
		return false
	}
	ok := *i%N == 0
	*i++
	return ok
}
