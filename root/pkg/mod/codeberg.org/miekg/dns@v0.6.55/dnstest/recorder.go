// Package dnstest allows for easy testing of DNS clients against a test server.
package dnstest

import (
	"net"
	"time"

	"codeberg.org/miekg/dns"
)

// Recorder is a type of ResponseWriter that captures the the message written to it. It will never perform an
// actual write. This effectively an [io.Discard] writer, and it's the caller's responsibility to write to the
// original dns.ResponseWriter. Usage in a handler:
//
//	rw := dnstest.NewRecorder(w)
//	ServeDNS(ctx, rw, r)
//	io.Copy(w, rw.Msg) // work on the original writer
//
// The msg is not unpacked during the Write, if you need this a rw.Msg.Unpack() is needed.
//
// Due to how we handle UDP sockets, it's impossible (hard?) to make the recorder write to the wrapped writer,
// so this must still be done separately, as shown above.
type Recorder struct {
	// In msg.go WriteTo we use the socket and then do a WriteMsgUDP to get the session right, this bypasses
	// the io.Writer stuff, thereby breaking the possibility to write here.
	w     dns.ResponseWriter
	Msg   *dns.Msg  // Msg contains the last message written.
	Start time.Time // Time when the recorder was created.
}

var _ dns.ResponseWriter = &Recorder{}

// NewRecorder makes and returns a new Recorder that wraps the given ResponseWriter. Start time set to now.
func NewRecorder(w dns.ResponseWriter) *Recorder { return &Recorder{w: w, Start: time.Now()} }

// NewTestRecorder returns a new Recorder that wraps a [dnstest.ResponseWriter]. This is a shortcut for
//
//	rec := dnstest.NewRecorder(&dnstest.ResponseWriter{})
//
// which is useful in tests.
func NewTestRecorder() *Recorder { return NewRecorder(&ResponseWriter{}) }

// NewTestRecorder6 works like [NewTestRecorder], but for IPv6.
func NewTestRecorder6() *Recorder { return NewRecorder(&ResponseWriter6{}) }

// MultiRecorder is a recorder that can record multiple messages written to it. Msg contains the last message
// written to it. None of the messages are Unpacked.
type MultiRecorder struct {
	*Recorder
	Msgs []*dns.Msg // Msgs contains all messages written to this recorder.
}

// NewMultiRecorder makes and returns a new MultiRecorder that wraps the given ResponseWriter. See
// [NewRecorder].
func NewMultiRecorder(w dns.ResponseWriter) *MultiRecorder {
	return &MultiRecorder{Recorder: NewRecorder(w)}
}

func (m *MultiRecorder) Write(b []byte) (int, error) {
	m.Msgs = append(m.Msgs, &dns.Msg{Data: make([]byte, len(b)-2)})
	return m.Recorder.Write(b)
}

func (r *Recorder) Write(b []byte) (int, error) {
	// See [Msg.WriteTo] that defaults to TCP.
	r.Msg = &dns.Msg{Data: make([]byte, len(b)-2)}
	copy(r.Msg.Data, b[2:])
	return len(b), nil
}

// Implement the net.Conn interface.
func (r *Recorder) Read(b []byte) (int, error)       { return len(b), nil }
func (r *Recorder) SetDeadline(time.Time) error      { return nil }
func (r *Recorder) SetReadDeadline(time.Time) error  { return nil }
func (r *Recorder) SetWriteDeadline(time.Time) error { return nil }

func (r *Recorder) Conn() net.Conn {
	// because of this everything defaults to "TCP"
	return r // we are a net.Conn ourselves
}

func (r *Recorder) Hijack() {
	if r.w != nil {
		r.w.Hijack()
	}
}

func (r *Recorder) Session() *dns.Session {
	if r.w != nil {
		return r.w.Session()
	}
	return nil
}

func (r *Recorder) Close() error {
	if r.w != nil {
		return r.w.Close()
	}
	return nil
}

func (r *Recorder) LocalAddr() net.Addr {
	if r.w != nil {
		return r.w.LocalAddr()
	}
	return nil
}

func (r *Recorder) RemoteAddr() net.Addr {
	if r.w != nil {
		return r.w.RemoteAddr()
	}
	return nil
}
