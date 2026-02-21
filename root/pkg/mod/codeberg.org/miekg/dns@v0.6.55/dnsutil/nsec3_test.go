package dnsutil

import (
	"testing"
)

func TestNSEC3Name(t *testing.T) {
	// cases from RFC 5155, Appendix A.
	testcases := []struct {
		in, exp string
	}{
		{"example.", "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM"},
		{"ns2.example.", "Q04JKCEVQVMU85R014C7DKBA38O0JI5R"},
		{"*.w.example.", "R53BQ7CC2UVMUBFU5OCMM6PERS9TK9EN"},
	}

	for i, tc := range testcases {
		got := NSEC3Name(tc.in, "aabbccdd", 12)
		if got != tc.exp {
			t.Errorf("test %d, expected %s, got %s", i, tc.exp, got)
		}
	}
}
