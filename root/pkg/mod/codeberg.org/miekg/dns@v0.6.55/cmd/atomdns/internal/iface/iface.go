// Package ifcace deals with interfaces.
package iface

import (
	"net"
)

// List returns a list of routable IP addresses from an interface.
func List(name string) []string {
	ifis, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addrs []net.Addr
	for _, ifi := range ifis {
		if ifi.Name == name {
			addrs, _ = ifi.Addrs()
		}
	}
	if len(addrs) == 0 {
		return nil
	}

	ips := []string{}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.IsLoopback() {
			continue
		}
		if ipnet.IP.IsPrivate() {
			continue
		}
		if ipnet.IP.IsLinkLocalUnicast() || ipnet.IP.IsUnspecified() {
			continue
		}
		ips = append(ips, ipnet.IP.String())
	}
	return ips
}
