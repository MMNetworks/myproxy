package dbfile

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
)

func (d *Dbfile) HandlerFuncTransfer(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if d.To == nil {
		m := new(dns.Msg)
		dnsutil.SetReply(m, r)
		m.Rcode = dns.RcodeRefused
		m.Data = r.Data

		m.Pack()
		io.Copy(w, m)
		return
	}
	z := d.Zone(dns.Zone(ctx))
	if err := dnszone.TransferOut(z, ctx, w, r); err != nil {
		log().Debug("Failure to transfer out", Err(err))
		return
	}
	alog := log().With(slog.String("zone", z.Origin()), slog.String("file", filepath.Base(z.Path)), slog.Any("upstream", w.RemoteAddr()), slog.Uint64("serial", uint64(dnszone.Serial(z))))
	alog.Info("Successful transfer out")
}

func (d *Dbfile) TransferIn(origin string) error {
	// save into temp file and then move this file over the dbfile path.
	c := dns.NewClient()
	m := dns.NewMsg(origin, dns.TypeAXFR)

	f, err := os.CreateTemp(filepath.Dir(d.Path), "xxxxx.transferred")
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(f.Name())

	for _, ip := range d.From.IPs {
		env, err := c.TransferIn(context.TODO(), m, "tcp", ip)
		if err != nil {
			continue
		}
		soa := 0
		for e := range env {
			if e.Error != nil {
				alog := log().With(slog.String("zone", origin), slog.String("path", filepath.Base(d.Path)))
				alog.Warn("Failed to transfer in", Err(err))
			}
			for _, rr := range e.Answer {
				if _, ok := rr.(*dns.SOA); ok {
					soa++
					if soa > 1 {
						continue
					}
				}
				io.WriteString(f, rr.String())
				f.Write([]byte("\n"))
			}
		}
		break
	}
	f.Close()
	alog := log().With(slog.String("zone", origin), slog.String("path", filepath.Base(d.Path)))
	alog.Info("Successful transfer in")
	return os.Rename(f.Name(), d.Path)
}
