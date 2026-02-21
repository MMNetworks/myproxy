package svcb

import (
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// This tests everything valid about SVCB but parsing. Parsing tests belong to parse_test.go.
func TestSVCB(t *testing.T) {
	svcbs := []struct {
		key  string
		data string
	}{
		{`mandatory`, `alpn,key65000`},
		{`alpn`, `h2,h2c`},
		{`port`, `499`},
		{`ipv4hint`, `3.4.3.2,1.1.1.1`},
		{`no-default-alpn`, ``},
		{`ipv6hint`, `1::4:4:4:4,1::3:3:3:3`},
		{`ech`, `YUdWc2JHOD0=`},
		{`dohpath`, `/dns-query{?dns}`},
		{`ohttp`, ``},
		{`key65000`, `4\ 3`},
		{`key65001`, `\"\ `},
		{`key65002`, ``},
		{`key65003`, `=\"\"`},
		{`key65004`, `\254\ \ \030\000`},
	}

	for _, o := range svcbs {
		keyCode := StringToKey(o.key)
		pairFn := KeyToPair(keyCode)
		if pairFn == nil {
			t.Error("failed to lookup svc key: ", o.key)
			continue
		}
		pair := pairFn()
		if PairToKey(pair) != keyCode {
			t.Error("key constant is not in sync: ", keyCode)
			continue
		}
		err := Parse(pair, o.data, "")
		if err != nil {
			t.Error("failed to parse svc pair: ", o.key)
			continue
		}

		b := make([]byte, pair.Len())
		off, err := _pack(pair, b, 0)
		if err != nil {
			t.Error("failed to pack value of svc pair: ", o.key, err)
			continue
		}
		if pair.Len() != off {
			t.Errorf("expected packed svc value %s to be of length %d but got %d", o.key, pair.Len(), off)
		}

		if str := pair.String(); str != o.data {
			t.Errorf("`%s' should be equal to\n`%s', but is     `%s'", o.key, o.data, str)
		}

		sc := cryptobyte.String(b[4:]) // skip the TLV
		err = _unpack(pair, &sc)
		if err != nil {
			t.Error("failed to unpack value of svc pair: ", o.key, err)
		}
	}
}

func TestALPNPresentation(t *testing.T) {
	tests := map[string]string{
		"h2":                "h2",
		"http":              "http",
		"\xfa":              `\250`,
		"some\"other,chars": `some\"other\\\044chars`,
	}
	for input, want := range tests {
		e := new(ALPN)
		e.Alpn = []string{input}
		if e.String() != want {
			t.Errorf("improper conversion with String(), wanted %v got %v", want, e.String())
		}
	}
}
