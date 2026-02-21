package global

import (
	"os"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
)

func TestSetup(t *testing.T) {
	cwd, _ := os.Getwd()
	testcases := []struct {
		input string
		exp   *Global
	}{
		{`root /tmp`, &Global{Root: "/tmp"}},
		{`root /tmp
		  debug`, &Global{Root: "/tmp"}},
		{`metrics /10 localhost`, &Global{MetricsN: 10, Root: cwd}},
	}
	for i, tc := range testcases {
		global := &Global{Root: tc.exp.Root}
		d := conffile.NewTestDispenser(tc.input)
		err := global.Setup(d)
		if err != nil {
			t.Fatal(err)
		}

		if tc.exp.Root != global.Root {
			t.Errorf("test %d: expected %s, got %s", i, tc.exp.Root, global.Root)
		}
		if tc.exp.MetricsN != global.MetricsN {
			t.Errorf("test %d: expected %d, got %d", i, tc.exp.MetricsN, global.MetricsN)
		}
	}
}
