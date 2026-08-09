//go:build !windows

// Package service provides the platform-neutral proxy entry point for myproxy.
//
// It exposes the public Service function used by the main entry point and
// coordinates the startup flow for the proxy runtime.
package service

import (
	"time"
)

// Service is the main entry point split by OS
func Service(args []string) {

	runProxy(args[:])
	time.Sleep(2 * time.Second)

}
