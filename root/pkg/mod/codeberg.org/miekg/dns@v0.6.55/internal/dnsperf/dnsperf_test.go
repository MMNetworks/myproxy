package dnsperf

import (
	"runtime"
	"strings"
	"testing"
)

const in = `DNS Performance Testing Tool
Version 2.14.0

[Status] Command line: dnsperf -s 127.0.0.1 -p 8053 -l 2 -c 8 -T 8 -d queries-files
[Status] Sending queries (to 127.0.0.1:8053)
[Status] Started at: Sun Aug 17 08:23:56 2025
[Status] Stopping after 2.000000 seconds
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         608050
  Queries completed:    608050 (100.00%)
  Queries lost:         0 (0.00%)

  Response codes:       NOERROR 608050 (100.00%)
  Average packet size:  request 32, response 92
  Run time (s):         2.000322
  Queries per second:   303976.059854

  Average Latency (s):  0.000145 (min 0.000008, max 0.005024)
  Latency StdDev (s):   0.000199
`

func TestQueriesPerSecond(t *testing.T) {
	r := strings.NewReader(in)
	qps, lost := queriesPerSecond(r)
	if lost != 0 {
		t.Errorf("expected %d lost queries, got %f", 0, lost)
	}

	if int(qps) != 303976 {
		t.Errorf("expected %d queries per second, got %d", 303976, int(qps))
	}
	nsPerOp := 1e9 / qps
	t.Logf("%s-%d\t%d\t\t\t%.1f ns/op\n", name, runtime.NumCPU(), int(qps), nsPerOp)
}
