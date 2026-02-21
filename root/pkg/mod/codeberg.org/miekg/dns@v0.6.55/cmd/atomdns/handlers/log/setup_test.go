package log

import (
	"reflect"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input string
		exp   *Log
	}{
		{`log {
			aaa/addr
			aaa/bloep
			bbb/addr
		}`, &Log{Contexts: map[string][]string{
			"aaa": {"addr", "bloep"},
			"bbb": {"addr"},
		}},
		},
	}
	for i, tc := range testcases {
		log := new(Log)
		co := dnsserver.NewTestController(tc.input)
		err := log.Setup(co)
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(tc.exp.Contexts, log.Contexts) {
			t.Errorf("test %d: expected %v, got %v", i, tc.exp.Contexts, log.Contexts)
		}
	}
}
