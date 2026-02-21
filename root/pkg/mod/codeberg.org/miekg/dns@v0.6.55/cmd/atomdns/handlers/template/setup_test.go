package template

import (
	"regexp"
	"slices"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Template
	}{
		{
			`template .* A {
                   		mytemplate
	        	}`,
			&Template{Regexp: regexp.MustCompile(".*"), Types: []uint16{dns.TypeA}, Path: "mytemplate"},
		},
		{
			`template .* {
                   		mytemplate
	        	}`,
			&Template{Regexp: regexp.MustCompile(".*"), Types: []uint16{}, Path: "mytemplate"},
		},
	}
	for i, tc := range testcases {
		template := new(Template)
		co := dnsserver.NewTestController(tc.input)
		err := template.Setup(co)
		if err != nil {
			t.Fatal(err)
		}
		if tc.exp.Path != template.Path {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Path, template.Path)
		}
		if tc.exp.Regexp.String() != template.Regexp.String() {
			t.Errorf("test %d, regexp, expected %s, got %s", i, tc.exp.Regexp.String(), template.Regexp.String())
		}
		for _, ty := range tc.exp.Types {
			if !slices.Contains(template.Types, ty) {
				t.Errorf("test %d: expected %v, got %v for types", i, tc.exp.Types, template.Types)
			}
		}
	}
}
