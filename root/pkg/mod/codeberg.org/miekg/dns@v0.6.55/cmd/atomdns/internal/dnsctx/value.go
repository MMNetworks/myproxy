package dnsctx

import (
	"context"
	"net/netip"
)

// Addr returns a netip.Addr from the context.
func Addr(ctx context.Context, key string) netip.Addr {
	x := Value(ctx, key)
	if x == nil {
		return netip.Addr{}
	}
	if a, ok := x.(netip.Addr); ok {
		return a
	}
	return netip.Addr{}
}

// String returns a string from the context under key.
func String(ctx context.Context, key string) string {
	x := Value(ctx, key)
	if x == nil {
		return ""
	}
	if s, ok := x.(string); ok {
		return s
	}
	return ""
}
