//go:build !go1.24

// Package readconfig provides TLS curve and cipher configuration helpers for myproxy.
//
// It defines the base mapping of TLS curve names to Go curve identifiers for
// supported Go versions.
package readconfig

import (
	"crypto/tls"
)

var curveMap = map[string]tls.CurveID{
	"P256":      tls.CurveP256,
	"P384":      tls.CurveP384,
	"P521":      tls.CurveP521,
	"CurveP256": tls.CurveP256,
	"CurveP384": tls.CurveP384,
	"CurveP521": tls.CurveP521,
	"X25519":    tls.X25519,
}
var curveMapExtra = map[string]tls.CurveID{} // overridden by version-specific files
