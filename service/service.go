//go:build !windows

package service

import (
	"time"
)

// Service is the main entry point split by OS
func Service(args []string) {

	runProxy(args[:])
	time.Sleep(2 * time.Second)

}
