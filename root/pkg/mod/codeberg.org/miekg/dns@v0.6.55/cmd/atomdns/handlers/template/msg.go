package template

import "codeberg.org/miekg/dns"

// Data is the structure that the template receives.
type Data struct {
	Zone  string
	ID    uint16
	Name  string
	Class string
	Type  string
	Msg   *dns.Msg

	ResponseWriter
}

// ResponseWriter holds all the data that can be extracted from the response writer via function from dnsutil.
type ResponseWriter struct {
	Family     int
	LocalIP    string
	LocalPort  string
	Network    string
	RemoteIP   string
	RemotePort string
}
