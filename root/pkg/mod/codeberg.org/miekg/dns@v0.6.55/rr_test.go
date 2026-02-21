package dns_test

import (
	"fmt"
	"strconv"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/crypto/cryptobyte"
)

// YO is a private RR: www.example.org. IN YO 10 Yo!
type YO struct {
	Hdr      dns.Header
	Priority uint8
	Yo       string `dns:"txt"`
}

const codepoint = 65281

// Typer interface.
func (rr *YO) Type() uint16 { return codepoint }

// RR interface.
func (rr *YO) Header() *dns.Header { return &rr.Hdr }
func (rr *YO) Len() int            { return rr.Hdr.Len() + 1 + len(rr.Yo) }
func (rr *YO) Data() dns.RDATA     { return nil } // Not implemented.
func (rr *YO) Clone() dns.RR       { return &YO{rr.Hdr, rr.Priority, rr.Yo} }
func (rr *YO) String() string {
	return rr.Header().Name + "\t" +
		strconv.FormatInt(int64(rr.Header().TTL), 10) + "\t" +
		dnsutil.ClassToString(rr.Header().Class) + "\tYO\t" +
		strconv.FormatUint(uint64(rr.Priority), 10) + " " + rr.Yo
}

// Packer interface
func (rr *YO) Pack(msg []byte, off int) (int, error) {
	if off+len(rr.Yo)+1 > len(msg) {
		return len(msg), fmt.Errorf("overflow packing YO")
	}
	msg[off] = rr.Priority
	off++
	copy(msg[off:off+len(rr.Yo)], rr.Yo)
	off += len(rr.Yo)
	return off, nil
}

func (rr *YO) Unpack(data []byte) error {
	s := cryptobyte.String(data)
	if !s.ReadUint8(&rr.Priority) {
		return fmt.Errorf("overflow unpacking YO")
	}
	var b []byte
	if !s.ReadBytes(&b, len(s)) {
		return fmt.Errorf("overflow unpacking YO")
	}
	rr.Yo = string(b)
	if !s.Empty() {
		return fmt.Errorf("trailing record data: %s", "YO")
	}
	return nil
}

// Parser interface.
func (rr *YO) Parse(tokens []string, _ string) error {
	if len(tokens) < 2 { // no rdata
		return nil
	}
	i, err := strconv.ParseUint(tokens[0], 10, 32)
	if err != nil || i > 255 {
		return fmt.Errorf("bad YO Priority")
	}
	rr.Priority = uint8(i)
	rr.Yo = tokens[1]
	return nil
}

func TestExternalRR(t *testing.T) {
	dns.TypeToRR[codepoint] = func() dns.RR { return new(YO) }
	dns.TypeToString[codepoint] = "YO"
	dns.StringToType["YO"] = codepoint

	y := &YO{Hdr: dns.Header{Name: "example.org.", Class: dns.ClassINET}, Priority: 10, Yo: "Yo!"}
	rry, err := dns.New(y.String())
	if err != nil {
		t.Fatal(err)
	}
	if rry.String() != y.String() {
		t.Fatal("YO string presentations should be identical")
	}

	m := dns.NewMsg("yo.example.org.", codepoint)
	m.Answer = []dns.RR{y}
	m.Pack()
	r := new(dns.Msg)
	r.Data = m.Data
	r.Unpack()

	if m.String() != r.String() {
		t.Fatal("YO presentation should survive Pack/Unpack")
	}
}

// YOOPT is a custom EDNS0 option for testing external EDNS0 support.
type YOOPT struct {
	Yo string
}

const optcodepoint = 65001

// Typer interface.
func (o *YOOPT) Type() uint16 { return optcodepoint }

// RR interface.
func (o *YOOPT) Header() *dns.Header { return &dns.Header{Name: "."} }
func (o *YOOPT) Data() dns.RDATA     { return o }
func (o *YOOPT) Len() int            { return 4 + len(o.Yo) } // 4 = TLV overhead (code + length)
func (o *YOOPT) Clone() dns.RR       { return &YOOPT{Yo: o.Yo} }
func (o *YOOPT) String() string      { return "YOOPT " + o.Yo }

// EDNS0 interface.
func (o *YOOPT) Pseudo() bool { return true }

// Packer interface.
func (o *YOOPT) Pack(msg []byte, off int) (int, error) {
	if off+len(o.Yo) > len(msg) {
		return len(msg), fmt.Errorf("overflow packing YOOPT")
	}
	copy(msg[off:], o.Yo)
	return off + len(o.Yo), nil
}

func (o *YOOPT) Unpack(yo []byte) error {
	o.Yo = string(yo)
	return nil
}

func TestExternalEDNS0(t *testing.T) {
	dns.CodeToRR[optcodepoint] = func() dns.EDNS0 { return new(YOOPT) }
	dns.CodeToString[optcodepoint] = "YOOPT"

	m := dns.NewMsg("yo.example.org.", dns.TypeA)
	m.Pseudo = []dns.RR{&YOOPT{Yo: "Yo!"}}

	if err := m.Pack(); err != nil {
		t.Fatalf("YOOPT failed to Pack: %v", err)
	}

	if err := m.Unpack(); err != nil {
		t.Fatalf("YOPT failed to Unpack %v", err)
	}

	if len(m.Pseudo) != 1 {
		t.Fatalf("expected 1 pseudo record, got %d", len(m.Pseudo))
	}

	y, ok := m.Pseudo[0].(*YOOPT)
	if !ok {
		t.Fatalf("pseudo record is not YOOPT, got %T", m.Pseudo[0])
	}
	if y.Yo != "Yo!" {
		t.Fatalf("expected Data 'Yo!', got '%s'", y.Yo)
	}
	if x := y.Type(); x != optcodepoint {
		t.Fatalf("expected type %d, got %d", optcodepoint, x)
	}
}
