package metrics

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input    string
		disabled bool
	}{
		{`metrics enable`, false},
		{`metrics disable`, true},
	}
	for i, tc := range testcases {
		metrics := new(Metrics)
		co := dnsserver.NewTestController(tc.input)
		err := metrics.Setup(co)
		if err != nil {
			t.Fatal(err)
		}

		if tc.disabled != metrics.disable {
			t.Errorf("test %d: expected %t, got %t", i, tc.disabled, metrics.disable)
		}
	}
}
