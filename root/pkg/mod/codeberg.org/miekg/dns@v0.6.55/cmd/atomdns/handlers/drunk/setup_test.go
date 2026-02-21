package drunk

import (
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func TestSetup(t *testing.T) {
	testcases := []struct {
		input     string
		shouldErr bool
		drop      uint64
		delay     uint64
		truncate  uint64
	}{
		// oks
		{`drunk`, false, 4, 0, 0},
		{`drunk {
			drop /2
			delay /3 1ms

		}`, false, 2, 3, 0},
		{`drunk {
			truncate /2
			delay /3 1ms

		}`, false, 0, 3, 2},
		{`erraric {
			drop /3
			delay
		}`, false, 3, 2, 0},
		// fails
		{`drunk {
			drop -1
		}`, true, 0, 0, 0},
		{`drunk {
			delay -1
		}`, true, 0, 0, 0},
		{`drunk {
			delay 1 2 4
		}`, true, 0, 0, 0},
		{`drunk {
			delay 15.a
		}`, true, 0, 0, 0},
		{`drunk {
			drop 3
			delay 3 bla
		}`, true, 0, 0, 0},
		{`drunk {
			truncate 15.a
		}`, true, 0, 0, 0},
		{`drunk {
			something-else
		}`, true, 0, 0, 0},
	}
	for i, tc := range testcases {
		co := dnsserver.NewTestController(tc.input)
		d := new(Drunk)
		err := d.Setup(co)
		if tc.shouldErr && err == nil {
			t.Errorf("test %d: expected error but found nil", i)
			continue
		} else if !tc.shouldErr && err != nil {
			t.Errorf("test %d: expected no error but found error: %v", i, err)
			continue
		}

		if tc.shouldErr {
			continue
		}

		if tc.delay != d.delay {
			t.Errorf("test %d: Expected delay %d but found: %d", i, tc.delay, d.delay)
		}
		if tc.drop != d.drop {
			t.Errorf("test %d: Expected drop %d but found: %d", i, tc.drop, d.drop)
		}
		if tc.truncate != d.truncate {
			t.Errorf("test %d: Expected truncate %d but found: %d", i, tc.truncate, d.truncate)
		}
	}
}
