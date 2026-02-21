package dnszone

import (
	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Hints give a hint to the functions here on what type of answer we got. This could be (mostly?) be done in
// retrieve, but requires redoing work already done, easier to just notify what we have.
type Hint int

const (
	hintAnswer Hint = iota
	hintDelegation
	hintWildcard
)

// Synthesize handles all wildcard responses, we are only called when we hit a wildcard and didn't find any
// more specific. I.e. original qname did not exist. Now we need to assemble the answer plus adding the NSECs
// that validate the answer. If sosynthesis.Name != encloser.Name, those two NSECs need to be added.
func Synthesize(z Interface, r *dns.Msg, sosynthesis, encloser *Node, re *Restart) *dns.Msg {
	// Synthesis, can still lead to no data if the qtype doesn't match.
	if len(sosynthesis.RRs) > 0 {
		qtype := dns.RRToType(r.Question[0])
		for _, rr := range sosynthesis.RRs {
			if dns.RRToType(rr) == qtype {
				rr1 := rr.Clone()
				rr1.Header().Name = r.Question[0].Header().Name // replace owner names with the qname
				r.Answer = append(r.Answer, rr1)
			}
			if r.Security {
				if _, ok := rr.(*dns.NSEC); ok {
					r.Ns = append(r.Ns, rr) // SoS' NSEC
				}
				if s, ok := rr.(*dns.RRSIG); ok {
					if s.TypeCovered == qtype {
						rr1 := rr.Clone()
						rr1.Header().Name = r.Question[0].Header().Name
						r.Answer = append(r.Answer, rr1)
					}
					if s.TypeCovered == dns.TypeNSEC {
						r.Ns = append(r.Ns, rr)
					}
				}

			}
		}
		if len(r.Answer) > 0 {
			return r
		}
		// NODATA, as the type isn't there, only need SOA + RRSIG.
		for _, rr := range z.Apex().RRs {
			if _, ok := rr.(*dns.SOA); ok {
				r.Ns = append(r.Ns, rr)
				continue
			}
			if r.Security {
				if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeSOA {
					r.Ns = append(r.Ns, rr)
				}
			}
		}
		return r
	}

	// NODATA response, when there are no RRs or when we fall through from above.
	if len(sosynthesis.RRs) == 0 {
		for _, rr := range z.Apex().RRs {
			if _, ok := rr.(*dns.SOA); ok {
				r.Ns = append(r.Ns, rr)
				continue
			}
			if r.Security {
				if _, ok := rr.(*dns.NSEC); ok {
					r.Ns = append(r.Ns, rr)
				}
				if s, ok := rr.(*dns.RRSIG); ok && (s.TypeCovered == dns.TypeSOA || s.TypeCovered == dns.TypeNSEC) {
					r.Ns = append(r.Ns, rr)
				}
			}
		}
		if r.Security { // proving there is no wildcard
			prev := z.Previous(r.Question[0].Header().Name)
			if !dns.EqualName(prev.Name, z.Origin()) { // we already have the SOA records, don't repeat.
				for _, rr := range prev.RRs {
					if _, ok := rr.(*dns.NSEC); ok {
						r.Ns = append(r.Ns, rr)
						continue
					}
					if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeNSEC {
						r.Ns = append(r.Ns, rr)
					}
				}
			}
		}
		return r
	}

	return r
}

func MsgFound(z Interface, r *dns.Msg, encloser *Node, hint Hint, re *Restart) *dns.Msg {
	section := &r.Answer
	qtype := dns.RRToType(r.Question[0])
	if hint == hintDelegation {
		r.Authoritative = false
		section = &r.Ns
		qtype = dns.TypeNS
	}

	// NXDOOMAIN response.
	if hint != hintDelegation && !dns.EqualName(encloser.Name, r.Question[0].Header().Name) {
		for _, rr := range z.Apex().RRs {
			if _, ok := rr.(*dns.SOA); ok {
				r.Ns = append(r.Ns, rr)
				continue
			}
			if r.Security {
				if _, ok := rr.(*dns.NSEC); ok {
					r.Ns = append(r.Ns, rr)
				}
				if s, ok := rr.(*dns.RRSIG); ok && (s.TypeCovered == dns.TypeSOA || s.TypeCovered == dns.TypeNSEC) {
					r.Ns = append(r.Ns, rr)
				}
			}
		}
		if r.Security {
			prev := z.Previous(r.Question[0].Header().Name)
			if !dns.EqualName(prev.Name, z.Origin()) {
				for _, rr := range prev.RRs {
					if _, ok := rr.(*dns.NSEC); ok {
						r.Ns = append(r.Ns, rr)
						continue
					}
					if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeNSEC {
						r.Ns = append(r.Ns, rr)
					}
				}
			}
		}
		if re != nil {
			r.Question[0].Header().Name = re.Name
		}
		r.Rcode = dns.RcodeNameError
		return r
	}

	// If this is a CNAME we need to chase it within the zone for (up to 8?) CNAME chains.
	for _, rr := range encloser.RRs {
		if dns.RRToType(rr) == dns.TypeCNAME && qtype != dns.TypeCNAME {
			return Canonical(z, r, encloser, re)
		}
	}
	if re != nil {
		// First answer in the chain must have the original qname.
		// But this is only true if we have a full chain. Use the saved re.Name
		r.Question[0].Header().Name = re.Name
		r.Answer = append(r.Answer, re.Answer...)
	}

	ds := false // if no DS is added we need an NSEC proofing it is not there.
	for _, rr := range encloser.RRs {
		if dns.RRToType(rr) == qtype {
			*section = append(*section, rr)
		}
		if hint == hintDelegation {
			if n, ok := rr.(*dns.NS); ok {
				// if the owner name is a child of the target we need to find the glue
				if dnsutil.IsBelow(rr.Header().Name, n.Ns) {
					if glue, ok := z.Get(n.Ns); ok {
						for _, rr := range glue.RRs {
							if _, ok := rr.(*dns.A); ok {
								r.Extra = append(r.Extra, rr)
								continue
							}
							if _, ok := rr.(*dns.AAAA); ok {
								r.Extra = append(r.Extra, rr)
							}
						}
					}
				}
			}
			if _, ok := rr.(*dns.DS); ok && r.Security {
				*section = append(*section, rr)
				ds = true
			}
		}
	}
	if r.Security {
		if hint == hintDelegation && !ds {
			for _, rr := range encloser.RRs {
				if dns.RRToType(rr) == dns.TypeNSEC {
					*section = append(*section, rr)
				}
				if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeNSEC {
					*section = append(*section, rr)
				}
			}
		}

		for _, rr := range encloser.RRs {
			if s, ok := rr.(*dns.RRSIG); ok {
				if s.TypeCovered == qtype {
					*section = append(*section, rr)
				}
				if hint == hintDelegation {
					if s.TypeCovered == dns.TypeDS {
						*section = append(*section, rr)
					}
				}
			}
		}
	}

	if len(*section) > 0 {
		return r
	}

	// NODATA response.
	for _, rr := range z.Apex().RRs {
		if _, ok := rr.(*dns.SOA); ok {
			r.Ns = append(r.Ns, rr)
			continue
		}
		if r.Security {
			if _, ok := rr.(*dns.NSEC); ok {
				r.Ns = append(r.Ns, rr)
			}
			if s, ok := rr.(*dns.RRSIG); ok && (s.TypeCovered == dns.TypeSOA || s.TypeCovered == dns.TypeNSEC) {
				r.Ns = append(r.Ns, rr)
			}
		}
	}

	return r
}

// Canonical follows the cname chain.
func Canonical(z Interface, r *dns.Msg, encloser *Node, re *Restart) *dns.Msg {
	if re == nil {
		re = &Restart{Name: r.Question[0].Header().Name}
	}

	for _, rr := range encloser.RRs {
		if c, ok := rr.(*dns.CNAME); ok {
			r.Question[0].Header().Name = c.Target
			re.Answer = append(re.Answer, rr)
			continue
		}
		if s, ok := rr.(*dns.RRSIG); ok && r.Security && s.TypeCovered == dns.TypeCNAME {
			re.Answer = append(re.Answer, rr)
		}
	}
	re.I++
	if re.I > 7 {
		r.Question[0].Header().Name = re.Name
		return r
	}
	return Retrieve(z, r, re)
}
