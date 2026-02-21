package dns

import (
	"testing"

	"codeberg.org/miekg/dns/internal/pack"
)

// BenchmarkCreateMsg benchmarks the creation of a small Msg with a question section only.
func BenchmarkMakeMsgQuestionMX(b *testing.B) {
	for b.Loop() {
		msg := new(Msg)
		msg.ID = ID()
		msg.RecursionDesired = true
		msg.Question = []RR{&MX{Hdr: Header{Name: "miek.nl."}}}
		msg.Pack()
	}
}

func BenchmarkPackName(b *testing.B) {
	name := "my.testserver.l.miek.nl."
	buf := make([]byte, 30)
	for b.Loop() {
		pack.Name(name, buf, 0, nil, false)
	}
}
