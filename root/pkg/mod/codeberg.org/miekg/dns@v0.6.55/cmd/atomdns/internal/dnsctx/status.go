package dnsctx

import (
	"context"
)

// Status returns boolean indicating if handler/status is set. If not found false is returned.
func Status(ctx context.Context, handler string) bool {
	x := ctx.Value(handler + "/" + KeyStatus)
	if x == nil {
		return false
	}
	return x.(bool)
}
