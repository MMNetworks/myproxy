//go:build go1.26

package readconfig

import (
	"crypto/tls"
)

var curveMapExtra = map[string]tls.CurveID{
	"P256":               tls.CurveP256,
	"P384":               tls.CurveP384,
	"P521":               tls.CurveP521,
	"CurveP256":          tls.CurveP256,
	"CurveP384":          tls.CurveP384,
	"CurveP521":          tls.CurveP521,
	"X25519":             tls.X25519,
	"X25519MLKEM768":     tls.X25519MLKEM768,
	"SecP256r1MLKEM768":  tls.SecP256r1MLKEM768,
	"SecP384r1MLKEM1024": tls.SecP384r1MLKEM1024,
}
