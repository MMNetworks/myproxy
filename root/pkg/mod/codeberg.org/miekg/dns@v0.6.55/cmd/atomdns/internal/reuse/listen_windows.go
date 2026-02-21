//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package reuse

import (
	"fmt"
	"net"
)

func ListenTCP(network, addr string, reuseport, reuseaddr bool) (net.Listener, error) {
	if reuseport || reuseaddr {
		// TODO(tmthrgd): return an error?
	}

	return net.Listen(network, addr)
}

func ListenUDP(network, addr string, reuseport, reuseaddr bool) (net.PacketConn, error) {
	if reuseport || reuseaddr {
		// TODO(tmthrgd): return an error?
	}

	return net.ListenPacket(network, addr)
}

// this is just for test compatibility
func checkReuseport(_ uintptr) (bool, error) {
	return false, fmt.Errorf("not supported")
}

// this is just for test compatibility
func checkReuseaddr(_ uintptr) (bool, error) {
	return false, fmt.Errorf("not supported")
}
