// Package implement a DNS zone, held in a binary tree. Each RR(set) that gets inserted will need to create
// any empty non-terminals (ENT) it possesses. I.e. inserting www.example.org into example.org is easy, but when
// www.a.b.c.example.org inserts we need to make sure that 'c.example.org', 'b.c.example.org' and
// 'a.b.c.example.org' also exist and are ENTs (have no actual RRs). For deleted the opposite must happen. As
// an example from RFC 4592, the record:  sub.*.example.  TXT  "this is not a wildcard" is a fun one. As this
// means the '*.example' ENT exists meaning that bogus.example. gets a NODATA response instead of NXDOMAIN.
//
// Doing this on insert sucks a bit, but makes the lookup code much more simple (and correct), which is more
// important for a DNS server.
//
// CNAME, DNSSEC, wildcards, etc. are all supported. Not supported is: DNAME (RFC 6672), the server will just
// return the DNAME without any of the (in the RFC required) post-processing.
package zone

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnszone"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/tidwall/btree"
)

// Zone holds the main zone and some meta data of the DNS zone we are serving.
// There is no locking, because after creation this structure is basically read-only.
// Tree will be used to write, but that has its own locking.
type Zone struct {
	origin string
	labels int
	Path   string
	Tree   *btree.BTreeG[*dnszone.Node]

	sync.RWMutex               // protects apex
	apex         *dnszone.Node // apex node, filled after a Load.
}

var _ dnszone.Interface = &Zone{}

func New(origin, path string) *Zone {
	z := &Zone{
		origin: dnsutil.Canonical(origin),
		labels: dnsutil.Labels(dnsutil.Canonical(origin)),
		Path:   func() string { a, _ := filepath.Abs(path); return a }(),
		Tree:   btree.NewBTreeG(dnszone.Less),
	}
	return z
}

func (z *Zone) Origin() string { return z.origin }
func (z *Zone) Labels() int    { return z.labels }

// Load loads a new zone with origin from path from z. Load also sets the apex, so the z.Apex can return that.
func (z *Zone) Load() error {
	f, err := os.Open(z.Path)
	if err != nil {
		return err
	}
	zp := dns.NewZoneParser(f, z.origin, z.Path)
	soa := 0
	// TODO(miek): various optimizations: gather names until we have a different one, then insert.
	// Downside: RR's are pointers so we need to empty out the structure and then refill it next time.
	// something Set also does.
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if _, ok := rr.(*dns.SOA); ok {
			soa++
		}
		z.Set(&dnszone.Node{Name: rr.Header().Name, RRs: []dns.RR{rr}})
	}
	if zp.Err() != nil {
		return fmt.Errorf("failed to parse zone %q with origin %q: %s ", z.Path, z.origin, zp.Err())
	}
	if soa != 1 {
		return fmt.Errorf("zone %q with origin %q has no SOA or not a single SOA record", z.Path, z.origin)
	}
	z.Lock()
	z.apex, _ = z.Tree.Get(&dnszone.Node{Name: z.origin})
	z.Unlock()
	return nil
}

func (z *Zone) Apex() *dnszone.Node {
	z.RLock()
	defer z.RUnlock()
	a := z.apex
	if a != nil {
		return a
	}
	return &dnszone.Node{}
}

// Set sets the RRs in the zone. It needs to create any empty non-terminals it has. Meaning for each label
// a lookup is done if there already is an empty non-terminal, if not an empty set is inserted.
// We should never be called to insert ENT (or names without RRs attached to them). The node's name is
// returned.
func (z *Zone) Set(node *dnszone.Node) string {
	// If the name already exist, we can just add our stuff to the node and we are done.
	n, ok := z.Tree.Get(node)
	if ok {
		n.RRs = append(n.RRs, node.RRs...)
		z.Tree.Set(n)
		return node.Name
	}
	// The name didn't exist before, we need to insert it.
	z.Tree.Set(node)
	// Now we need to create (potential) ENT up to the apex. So when just insert www.a.b.example.org. We need
	// make a.b.example.org, b.example.org. So we need N+2 labels, if this zone has N labels. If we only have
	// 1 label more, we just created the correct node.
	labels := dnsutil.Labels(node.Name)
	if labels == z.Labels()+1 {
		return node.Name
	}

	// Else we create (or check if they exist) the intermediate nodes.
	off := 0
	name := node.Name
	for i := 1; i < labels-z.Labels(); i++ {
		off, _ = dnsutil.Next(name, off)

		node := &dnszone.Node{Name: name[off:]}
		if _, ok := z.Tree.Get(node); ok {
			continue // already exist, nothing to add
		}
		z.Tree.Set(node) // set an empty node
	}
	return node.Name
}

// Get gets the node under name from z.
func (z *Zone) Get(name string) (*dnszone.Node, bool) {
	n, ok := z.Tree.Get(&dnszone.Node{Name: name})
	if ok {
		return n, true
	}
	return nil, false
}

// Previous returns the logical previous name from name.
func (z *Zone) Previous(name string) *dnszone.Node {
	node := &dnszone.Node{}
	z.Tree.Descend(&dnszone.Node{Name: name}, func(n *dnszone.Node) bool {
		node = n
		return false
	})
	return node
}
