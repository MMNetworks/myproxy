package dnszone

import "codeberg.org/miekg/dns"

// Interface defines the methods for each db* implementation. This is currently unused, and if used
// this needs to live in the pkg/db or something, not tucked away here.
//
// This is the interface dbfile implements on top of the b-tree. And dbsqlite on top of an SQLite database.
type Interface interface {
	// Load loads a zone.
	Load() error
	// Get returns the node under key. The boolean is true when something is found.
	Get(string) (*Node, bool)
	// Previous returns the previous node for string. If the node under key exists that one is returned.
	Previous(string) *Node
	// Set sets a node in the zone. It must take care to also fill out any empty non-terminals that are
	// needed.
	Set(*Node) string
	// Apex returns the apex of the zone. If the apex/zone is not there yet, this method must return an empty
	// node, not nil.
	Apex() *Node
	// Origin returns the origin of the zone as string.
	Origin() string
	// Labels returns the number of labels from the origin. This is method to allow the implementation some
	// head room for optimizations.
	Labels() int
	// Walk walks the entire walk starting at the apex.
	Walk(func(*Node) bool)
	// AuthoritativeWalk walks the entire zone starting at the apex, but skips non-authoritative records:
	// delegated (or should have been delegated) and glue recors.
	AuthoritativeWalk(func(*Node, bool) bool)
}

// Serial returns the SOA serial number of z, 0 is returned if there is none.
func Serial(z Interface) uint32 {
	apex := z.Apex()
	for _, rr := range apex.RRs {
		if s, ok := rr.(*dns.SOA); ok {
			return s.Serial
		}
	}
	return 0
}
