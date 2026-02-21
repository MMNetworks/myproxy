package dnsutil

import "testing"

func TestCommon(t *testing.T) {
	testcases := []struct {
		a   string
		b   string
		exp int
	}{

		{"www.miek.nl.", "miek.nl.", 2},
		{"www.miek.nl.", "miek.nl", 0}, // not fully qualified
		{"www.miek.nl.", "www.bla.nl.", 1},
		{"www.bla..nl.", "ml.www.bla.", 0},
		{"www.miek.nl.", "nl.", 1},
		{"www.miek.nl.", "miek.nl.", 2},
		{".", ".", 0},
		{"example.org.", "EXAMPLE.ORG.", 2},
	}
	for _, tc := range testcases {
		got := Common(tc.a, tc.b)
		if got != tc.exp {
			t.Errorf("expected %d, got %d, for %s/%s", tc.exp, got, tc.a, tc.b)
		}
	}
}
