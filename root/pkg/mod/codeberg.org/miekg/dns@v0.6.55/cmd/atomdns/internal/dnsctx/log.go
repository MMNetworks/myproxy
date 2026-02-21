package dnsctx

import (
	"context"
	"log/slog"
)

// Id returns a slog.Attr that either is empty or contains the request id as added by the id handler.
func Id(ctx context.Context) slog.Attr {
	id := slog.Attr{}
	if x := String(ctx, "id/id"); x != "" {
		id = slog.Group("id", slog.String("id", x))
	}
	return id
}
