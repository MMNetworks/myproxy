package dnszone

import (
	"strings"

	"codeberg.org/miekg/dns"
)

// Restart is used in the (recursive) calling of Retrieve to complete a CNAME chain. The i index is used to avoid loops
// in the recursion and we break at 8.
type Restart struct {
	Name   string   // original qname that started this sequence
	Answer []dns.RR // current set of RRs that need to go in the final response
	I      int      // break recursion at I > 7
}

// A Node is a DNS node in the tree.
type Node struct {
	Name string
	RRs  []dns.RR // all the rrs with owner name 'name'.
}

func (n *Node) String() string {
	// TODO(miek): builderPool for all of these?
	sb := strings.Builder{}
	for i := range n.RRs {
		sb.WriteString(n.RRs[i].String())
		sb.WriteByte('\n')
	}
	return sb.String()
}

// Less compares nodes a, b by Name and returns true if a is less than b.
func Less(a, b *Node) bool { return dns.CompareName(a.Name, b.Name) == -1 }
