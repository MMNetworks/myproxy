package dnsstring

import "testing"

func TestReader(t *testing.T) {
	in := "aaa. 3600 IN NS a.nic.aaa."
	r := NewReader(in)
	p := make([]byte, 30)
	_, err := r.Read(p)
	if err != nil {
		t.Fatal("expected no error, but got one")
	}
	// second read, should inlude a newline
	p = make([]byte, 30)
	_, err = r.Read(p)
	if err == nil {
		t.Fatal("expected error (io.EOF), but got none")
	}
	if p[0] != '\n' {
		t.Fatalf("expected '\n', got %c", p[0])
	}
}
