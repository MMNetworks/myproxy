package pack

import (
	"fmt"
	"maps"
	"testing"
)

func TestName(t *testing.T) {
	newmap := func(a ...any) map[string]uint16 {
		m := map[string]uint16{}
		for i := 0; i < len(a); i += 2 {
			m[a[i].(string)] = uint16(a[i+1].(int))
		}
		return m
	}

	testcases := []struct {
		in   string
		ok   bool
		comp map[string]uint16
	}{
		{`www.this.is.an.example.org.`, true, newmap("this.is.an.example.org.", 4, "www.this.is.an.example.org.", 0,
			"an.example.org.", 12, "example.org.", 15, "is.an.example.org.", 9, "org.", 23)},
		{`www.example.org.`, true, newmap("www.example.org.", 0, "example.org.", 4, "org.", 12)},
		{`www.example.org`, false, nil},
		{`org.`, true, newmap("org.", 0)},
		{`.`, true, newmap()},
		{`..`, false, nil},
		{`.org`, false, nil},
		{`www..example.org.`, false, nil},
		{`www.example.org..`, false, nil},
	}
	buf := make([]byte, 256)
	for i, tc := range testcases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			comp := map[string]uint16{}
			_, got := Name(tc.in, buf, 0, comp, true)
			if (got == nil) != tc.ok {
				t.Errorf("expected %t for name %q: %v", tc.ok, tc.in, got)
			}
			if !tc.ok {
				return
			}
			if !maps.Equal(comp, tc.comp) {
				t.Errorf("expected compression map\n %v, got\n %v", tc.comp, comp)
			}
		})
	}
}

func BenchmarkName(b *testing.B) {
	buf := make([]byte, 256)
	s := "wwww.example.org."
	for b.Loop() {
		Name(s, buf, 0, nil, false)
	}
}
