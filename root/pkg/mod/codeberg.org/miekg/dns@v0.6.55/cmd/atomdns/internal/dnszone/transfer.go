package dnszone

import (
	"context"
	"fmt"
	"sync"

	"codeberg.org/miekg/dns"
)

func TransferOut(z Interface, ctx context.Context, w dns.ResponseWriter, r *dns.Msg) error {
	w.Hijack()
	env := make(chan *dns.Envelope)
	c := dns.NewClient()
	var wg sync.WaitGroup

	i := 0
	ch := make(chan error)
	wg.Go(func() {
		err := c.TransferOut(w, r, env)
		w.Close()
		ch <- err
	})

	apex := z.Apex()
	z.Walk(func(n *Node) bool {
		if len(n.RRs) == 0 { // skip empty non-terminals
			return true
		}
		env <- &dns.Envelope{Answer: n.RRs}
		i++
		return true
	})
	for _, rr := range apex.RRs {
		if s, ok := rr.(*dns.SOA); ok {
			i++
			env <- &dns.Envelope{Answer: []dns.RR{s}}
		}
	}

	close(env)
	err := <-ch
	if i == 0 {
		return fmt.Errorf("no RRs transferred")
	}
	return err
}
