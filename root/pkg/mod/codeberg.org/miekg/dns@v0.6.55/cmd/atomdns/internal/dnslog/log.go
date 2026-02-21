package dnslog

import (
	"context"
	"log/slog"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
)

func PackFail(ctx context.Context, log *slog.Logger, err slog.Attr) {
	const packFail = "Pack failure"
	log.With(dnsctx.Id(ctx)).Debug(packFail, err)
}
