package template_test

import (
	"context"
	"regexp"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/atomtest"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/template"
	"codeberg.org/miekg/dns/dnstest"
)

func TestTemplate(t *testing.T) {
	te := &template.Template{Path: "testdata/msg.go.tmpl", Regexp: regexp.MustCompile(".*")}

	m := dnstest.NewMsg()
	tw := dnstest.NewTestRecorder()
	te.HandlerFunc(atomtest.Noop).ServeDNS(context.TODO(), tw, m)

	tw.Msg.Unpack()
	if tw.Msg.ID != m.ID {
		t.Fatalf("expected %d, got %d", m.ID, tw.Msg.ID)
	}
	if len(tw.Msg.Answer) != 1 {
		t.Fatalf("expected answer section of %d, got %d", 1, len(tw.Msg.Answer))
	}
}
