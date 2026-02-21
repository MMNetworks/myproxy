package kill

import (
	"codeberg.org/miekg/dns"
)

type Kill int

func (k *Kill) HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc { return nil }
