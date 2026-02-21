package atomhttp

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/global"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/reuse"
	"codeberg.org/miekg/dns/dnshttp"
	"golang.org/x/net/netutil"
)

// ServeHTTP implements the http.Handler and is the bridge between the HTTP and DNS worlds.
// It the request and converts to the DNS format, calls the handlers, converts it back and writes it to the client.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m, err := dnshttp.Request(r)
	if err != nil {
		h.MsgInvalidFunc(m, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hw := dnshttp.NewResponseWriter(w, r, r.Context().Value(http.LocalAddrContextKey).(net.Addr))
	h.mux.ServeDNS(context.Background(), hw, m)
}

type Server struct {
	server   *http.Server
	Listener net.Listener
}

func Serve(ch chan error, s *Server, global *global.Global) {
	l, err := reuse.ListenTCP("tcp", s.server.Addr, true, true)
	if err != nil {
		ch <- err
		return
	}
	ll := l
	if x := global.HttpLimits.MaxInflight; x > 0 {
		ll = netutil.LimitListener(l, x)
	}
	lt := ll
	if global.TlsConfig != nil {
		lt = tls.NewListener(l, global.TlsConfig)
	}
	if global.TlsCertConfig != nil {
		tlsConfig := global.TlsCertConfig.TLSConfig()
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, dnshttp.NextProtos...)
		lt = tls.NewListener(l, tlsConfig)
	}
	go func() {
		if err := s.server.Serve(lt); err != nil {
			ch <- err
			return
		}
	}()
	s.Listener = lt
	ch <- nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.server.Shutdown(ctx)
	return nil
}

func New(addr string, mux *dns.ServeMux, fn dns.InvalidMsgFunc) *Server {
	s := new(Server)
	h := newHandler(mux, fn)
	logger := slog.NewLogLogger(slog.Default().Handler(), slog.LevelError)
	s.server = &http.Server{Addr: addr, Handler: h, ErrorLog: logger, ReadTimeout: 5 * time.Second}
	return s
}

type handler struct {
	mux            *dns.ServeMux
	MsgInvalidFunc dns.InvalidMsgFunc
}

func newHandler(mux *dns.ServeMux, fn dns.InvalidMsgFunc) *http.ServeMux {
	hmux := http.NewServeMux()
	handler := &handler{mux: mux, MsgInvalidFunc: fn}
	hmux.Handle("/dns-query", handler)
	return hmux
}
