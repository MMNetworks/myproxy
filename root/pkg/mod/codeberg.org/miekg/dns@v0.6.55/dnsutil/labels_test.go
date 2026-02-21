package dnsutil

import (
	"testing"
)

func TestJoin(t *testing.T) {
	testcases := []struct {
		in  []string
		out string
	}{
		{[]string{"bla", "bliep", "example", "org"}, "bla.bliep.example.org."},
		{[]string{"example", "."}, "example."},
		{[]string{"example", "org."}, "example.org."}, // technically we should not be called like this.
		{[]string{"."}, "."},
	}

	for i, tc := range testcases {
		if x := Join(tc.in...); x != tc.out {
			t.Errorf("test %d, expected %s, got %s", i, tc.out, x)
		}
	}
}

func TestNext(t *testing.T) {
	type next struct {
		string
		int
	}
	testcases := map[next]int{
		{"", 1}:             0,
		{"www.miek.nl.", 0}: 4,
		{"www.miek.nl.", 4}: 9,
		{"www.miek.nl.", 9}: 12,
	}
	for tc, i := range testcases {
		x, ok := Next(tc.string, tc.int)
		if i != x {
			t.Errorf("label should be %d, got %d, %t: next %d, %s", i, x, ok, tc.int, tc.string)
		}
	}
}

func TestPrev(t *testing.T) {
	type prev struct {
		string
		int
	}
	testcases := map[prev]int{
		{"", 1}:             0,
		{"www.miek.nl.", 0}: 12,
		{"www.miek.nl.", 1}: 9,
		{"www.miek.nl.", 2}: 4,

		{"www.miek.nl", 0}: 11,
		{"www.miek.nl", 1}: 9,
		{"www.miek.nl", 2}: 4,

		{"www.miek.nl.", 5}: 0,
		{"www.miek.nl", 5}:  0,

		{"www.miek.nl.", 3}: 0,
		{"www.miek.nl", 3}:  0,
	}
	for s, i := range testcases {
		x, ok := Prev(s.string, s.int)
		if i != x {
			t.Errorf("label should be %d, got %d, %t: previous %d, %s", i, x, ok, s.int, s.string)
		}
	}
}

func TestLabels(t *testing.T) {
	testcases := map[string]int{
		"www.miek.nl.": 3,
		"www.miek.nl":  3,
		"nl":           1,
		".":            0,
	}
	for tc, i := range testcases {
		x := Labels(tc)
		if x != i {
			t.Errorf("labels should have %d, got %d", i, x)
		}
	}
}

func TestCanonical(t *testing.T) {
	for s, expect := range map[string]string{
		"":                 ".",
		".":                ".",
		"tld":              "tld.",
		"tld.":             "tld.",
		"example.test":     "example.test.",
		"Lower.CASE.test.": "lower.case.test.",
		"*.Test":           "*.test.",
		"ÉxamplE.com":      "Éxample.com.",
		"É.com":            "É.com.",
	} {
		if got := Canonical(s); got != expect {
			t.Errorf("Canonical(%q) = %q, expected %q", s, got, expect)
		}
	}
}

func TestIsName(t *testing.T) {
	testcases := map[string]bool{
		".":                 true,
		"..":                false,
		"double-dot..test":  false,
		".leading-dot.test": false,
		"@.":                true,
		"www.example.com":   true,
		"www.e%ample.com":   true,
		"www.example.com.":  true,
		"mi\\k.nl.":         true,
		"mi\\k.nl":          true,
	}
	for tc, ok := range testcases {
		ok1 := IsName(tc)
		if ok != ok1 {
			t.Errorf("have %t for %s ", ok, tc)
		}
	}
}
