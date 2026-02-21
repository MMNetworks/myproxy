package dbsqlite

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
)

func (d *Dbsqlite) HandlerFuncTransfer(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if d.To == nil {
		m := new(dns.Msg)
		dnsutil.SetReply(m, r)
		m.Rcode = dns.RcodeRefused
		m.Data = r.Data

		m.Pack()
		io.Copy(w, m)
		return
	}
	z := d.Zones[dns.Zone(ctx)]
	if err := dnszone.TransferOut(z, ctx, w, r); err != nil {
		log().Debug("Failure to transfer out", Err(err))
		return
	}
	alog := log().With(slog.String("zone", z.Origin()), slog.String("path", filepath.Base(d.Path)), slog.Any("upstream", w.RemoteAddr()), slog.Uint64("serial", uint64(dnszone.Serial(z))))
	alog.Info("Successful transfer out")
}
