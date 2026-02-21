package template

import (
	"bytes"
	"context"
	"io"
	"os"
	"regexp"
	"slices"
	"sync"
	"text/template"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnslog"
	"codeberg.org/miekg/dns/dnsutil"
)

type Template struct {
	Path   string
	Regexp *regexp.Regexp
	Types  []uint16
}

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

func (t *Template) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc {
	return dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		if len(t.Types) > 0 && !slices.Contains(t.Types, dns.RRToType(r.Question[0])) {
			next.ServeDNS(ctx, w, r)
			return
		}
		if !t.Regexp.MatchString(r.Question[0].Header().Name) {
			next.ServeDNS(ctx, w, r)
			return
		}
		funcs := template.FuncMap{
			"ctx": func(key string) any { return dnsctx.Value(ctx, key) },
		}
		var err error
		tmpl := template.New(t.Path).Funcs(funcs)
		text, err := os.ReadFile(t.Path)
		if err != nil {
			log().With(dnsctx.Id(ctx)).Warn("Failed to find or parse", "path", t.Path)
			next.ServeDNS(ctx, w, r) // call next so we hit the refused at some point
			return
		}
		tmpl, err = tmpl.Parse(string(text))
		if err != nil {
			log().With(dnsctx.Id(ctx)).Warn("Failed to find or parse", "path", t.Path)
			next.ServeDNS(ctx, w, r) // call next so we hit the refused at some point
			return
		}

		data := &Data{Zone: dns.Zone(ctx), ID: r.ID, Msg: r, Name: r.Question[0].Header().Name,
			Class: dns.ClassToString[r.Question[0].Header().Class],
			Type:  dns.TypeToString[dns.RRToType(r.Question[0])],
			ResponseWriter: ResponseWriter{
				Family:     dnsutil.Family(w),
				LocalIP:    dnsutil.LocalIP(w),
				LocalPort:  dnsutil.LocalPort(w),
				Network:    dnsutil.Network(w),
				RemoteIP:   dnsutil.RemoteIP(w),
				RemotePort: dnsutil.RemotePort(w),
			},
		}

		buf := bufPool.Get().(*bytes.Buffer)
		err = tmpl.Execute(buf, data)
		if err != nil {
			buf.Reset()
			bufPool.Put(buf)
			log().With(dnsctx.Id(ctx)).Warn("Failed to execute template", "path", t.Path, Err(err))
			next.ServeDNS(ctx, w, r)
			return
		}

		m, err := dnsutil.StringToMsg(buf.String())
		buf.Reset()
		bufPool.Put(buf)
		if err != nil {
			dnsutil.SetReply(m, r)
			m.Rcode = dns.RcodeServerFailure
		}
		m.Data = r.Data

		m = dnsctx.Funcs(ctx, m)
		if err := m.Pack(); err != nil {
			dnslog.PackFail(ctx, log(), Err(err))
		}
		io.Copy(w, m)
	})
}
