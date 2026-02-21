package sign

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers/dbfile/zone"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// Sign signs the zone with origin from s. It returns the signed zone.
func (s *Sign) Sign(origin string) (*zone.Zone, error) {
	z := zone.New(origin, s.Path)
	err := z.Load()
	if err != nil {
		return z, err
	}
	alog := log().With(slog.String("zone", origin))
	now := time.Now()

	n := &dnszone.Node{Name: origin}
	for _, pair := range s.KeyPairs {
		n.RRs = append(n.RRs, pair.DNSKEY)
		n.RRs = append(n.RRs, pair.ToDS(dns.SHA1).ToCDS())
		n.RRs = append(n.RRs, pair.ToDS(dns.SHA256).ToCDS())
		n.RRs = append(n.RRs, pair.ToCDNSKEY())
	}
	z.Set(n)

	// Add nsecs + rrsig in the first pass.
	nf := &nsecfn{keypairs: s.KeyPairs, ttl: s.ttl, origin: origin, zonemd: s.Zonemd}
	z.AuthoritativeWalk(nf.Walk)
	for i := range nf.nsecs {
		z.Set(nf.nsecs[i])
	}
	z.Set(nf.Last(z.Origin()))

	// Now walk again to sign the rest.
	rrset := []dns.RR{}
	incep, expir := lifetime(time.Now().UTC())

	options := &dns.SignOption{Pooler: s.pool}
	z.AuthoritativeWalk(func(n *dnszone.Node, auth bool) bool {
		if len(n.RRs) == 0 || !auth {
			return true
		}
		types := types(n, s.ttl)
		for _, t := range types {
			if t == dns.TypeRRSIG {
				continue
			}
			if t == dns.TypeNS && len(n.Name) > len(z.Origin()) { // delegation NS
				continue
			}

			rrset = rrset[:0]
			for _, rr := range n.RRs {
				if dns.RRToType(rr) == t {
					if t == dns.TypeSOA {
						rr.(*dns.SOA).Serial = uint32(time.Now().Unix())
					}
					rrset = append(rrset, rr)
				}
			}

			for _, pair := range s.KeyPairs {
				rrsig := dns.NewRRSIG(origin, pair.Algorithm, pair.Tag, incep, expir)
				if err := rrsig.Sign(pair.Signer, rrset, options); err != nil {
					alog.Error("Failed to sign", Err(err))
					return false
				}
				n.RRs = append(n.RRs, rrsig)
			}
		}
		return true
	})
	if !s.Zonemd {
		Duration.WithLabelValues(z.Origin()).Set(float64(time.Since(now)))
		return z, nil
	}

	zonemd := &dns.ZONEMD{Hdr: dns.Header{Name: origin, Class: dns.ClassINET, TTL: s.ttl}, ZONEMD: rdata.ZONEMD{Scheme: dns.ZONEMDSchemeSimple, Hash: dns.ZONEMDHashSHA384}}
	zone := []dns.RR{}
	z.Walk(func(n *dnszone.Node) bool {
		zone = append(zone, n.RRs...)
		return true
	})

	sort.Sort(dns.RRset(zone))
	zonemd.Sign(zone, &dns.ZONEMDOption{})

	apex := z.Apex()
	apex.RRs = append(apex.RRs, zonemd)

	for _, pair := range s.KeyPairs {
		rrsig := dns.NewRRSIG(origin, pair.Algorithm, pair.Tag, incep, expir)
		rrsig.Sign(pair.Signer, []dns.RR{zonemd}, options)
		apex.RRs = append(apex.RRs, rrsig)
	}

	Duration.WithLabelValues(z.Origin()).Set(float64(time.Since(now)))
	return z, nil
}

type nsecfn struct {
	origin   string
	zonemd   bool
	keypairs []KeyPair

	last   string
	bitmap []uint16
	ttl    uint32

	nsecs []*dnszone.Node
}

func types(n *dnszone.Node, ttl uint32) []uint16 {
	// while looking at them anyway we set the ttl.
	types := []uint16{}
	for j := range n.RRs {
		types = append(types, dns.RRToType(n.RRs[j]))
		n.RRs[j].Header().TTL = ttl
	}
	types = append(types, []uint16{dns.TypeRRSIG, dns.TypeNSEC}...)

	slices.Sort(types)
	return slices.Compact(types)
}

// Walk is used when signing a zone. It generates all the NSECs that a zone needs.
// We can't insert while walking, so we need save the nsec+rssig and insert them post walk.
func (nf *nsecfn) Walk(n *dnszone.Node, auth bool) bool {
	if len(n.RRs) == 0 || !auth { // empty non-terminal
		return true
	}

	if nf.last != "" {
		nsecnode := nf.nsec(n.Name)
		nf.nsecs = append(nf.nsecs, nsecnode)
	}
	nf.last = n.Name
	nf.bitmap = types(n, nf.ttl)
	if nf.zonemd && dns.EqualName(nf.origin, n.Name) {
		nf.bitmap = append(nf.bitmap, dns.TypeZONEMD)
		slices.Sort(nf.bitmap)
	}
	return true
}

// Last creates the last NSEC, that loops back to the origin. Walk misses this.
func (nf *nsecfn) Last(origin string) *dnszone.Node { return nf.nsec(origin) }

// nsec creates an NSEC node from nf.
func (nf *nsecfn) nsec(name string) *dnszone.Node {
	nsec := &dns.NSEC{
		Hdr:  dns.Header{Name: nf.last, TTL: nf.ttl, Class: dns.ClassINET},
		NSEC: rdata.NSEC{NextDomain: name, TypeBitMap: nf.bitmap},
	}
	nsecnode := &dnszone.Node{Name: nf.last}
	nsecnode.RRs = append(nsecnode.RRs, nsec)
	return nsecnode
}

// lifetime returns signature incep, expire timestamp used in the signature creation.
func lifetime(now time.Time) (uint32, uint32) {
	incep := uint32(now.Add(signatureInception).Add(inceptionJitter).Unix())
	expir := uint32(now.Add(signatureExpire).Add(expirationJitter).Unix())
	return incep, expir
}

// Expired returns true when 'a' signature on the SOA record has only 9 days left.
func (s *Sign) Expired(origin string) (bool, error) {
	f, err := os.Open(s.Zones[origin].Path + Signed)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	now := time.Now().UTC()
	zp := dns.NewZoneParser(f, origin, f.Name())
	i := 0
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == dns.TypeSOA {
			alog := log().With(slog.String("zone", origin), slog.String("path", filepath.Base(f.Name())))
			if !s.ValidPeriod(now) {
				alog.Warn("Signature's validity period has passed")
				return true, nil
			}
			expire, _ := time.Parse("20060102150405", dnsutil.TimeToString(s.Expiration))
			Expire.WithLabelValues(origin).Set(float64(expire.Unix()))
			days := Expired(now, expire)
			if days < 15 {
				alog.Warn("Days left before expiration", slog.Int("days", days))
			} else {
				alog.Info("Days left before expiration", slog.Int("days", days))
			}
			return days < expireDays, nil
		}

		i++
		if i > 50 {
			break
		}
	}
	if zp.Err() != nil {
		return false, fmt.Errorf("failed to parse zone %q with origin %q: %s ", s.Zones[origin].Path, origin, zp.Err())
	}
	return true, fmt.Errorf("no SOA signature found in first 50 records")
}

// Expired returns an integer saying how many days expire is still valid taking now as a starting point.
func Expired(now, expire time.Time) int {
	left := expire.Sub(now)
	return int(left / Day)
}

func (s Sign) Write(z *zone.Zone) error {
	f, err := os.CreateTemp(s.Directory, "atomdns")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	z.Walk(func(n *dnszone.Node) bool {
		if len(n.RRs) == 0 { // skip empty non-terminals
			return true
		}
		io.WriteString(f, n.String())
		return true
	})
	f.Close()
	target := filepath.Join(s.Directory, filepath.Base(z.Path)+Signed)
	return os.Rename(f.Name(), target)
}
