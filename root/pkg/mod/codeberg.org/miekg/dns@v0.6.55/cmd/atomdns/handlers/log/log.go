package log

import (
	"context"
	"log/slog"
	"net"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/dnsutil"
)

type Log struct {
	Contexts map[string][]string
	UnixAddr string
}

func (l *Log) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if !state.Load() {
			next.ServeDNS(ctx, w, r)
			return
		}

		ecs := slog.Attr{}
		if a := dnsctx.Addr(ctx, "ecs/addr"); a.IsValid() {
			ecs = slog.Group("ecs", slog.Any("addr", a))
		}

		_, unix := w.RemoteAddr().(*net.UnixAddr)
		log := slog.Default().
			With(dnsctx.Id(ctx)).
			With("network", func() string {
				if unix {
					return "unix"
				}
				return dnsutil.Network(w)
			}()).
			With("remote", func() string {
				if unix {
					return l.UnixAddr
				}
				return dnsutil.RemoteIP(w)
			}()).
			With("port", dnsutil.RemotePort(w)).
			With(ecs).
			With(slog.Int("id", int(r.ID))).
			With("type", func() string { _, t := dnsutil.Question(r); return dnsutil.TypeToString(t) }()).
			With("class", dnsutil.ClassToString(r.Question[0].Header().Class)).
			With("name", func() string { z, _ := dnsutil.Question(r); return z }()).
			With(slog.Int("size", len(r.Data))).
			With(slog.Int("bufsize", func() int {
				if r.UDPSize < 512 {
					return 512
				}
				return int(r.UDPSize)
			}())).
			With("opcode", dnsutil.OpcodeToString(r.Opcode))

		groups := []slog.Attr{}
		for key, values := range l.Contexts {
			attrs := make([]any, 0, len(values))
			for _, v := range values {
				if x := dnsctx.Value(ctx, key+"/"+v); x != nil {
					attrs = append(attrs, slog.Any(v, x))
				}
			}
			if len(attrs) > 0 {
				groups = append(groups, slog.Group(key, attrs...))
			}
		}
		for _, group := range groups {
			log = log.With(group)
		}

		log.Info(dns.Zone(ctx))

		next.ServeDNS(ctx, w, r)
	})
}
