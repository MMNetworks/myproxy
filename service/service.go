//go:build !windows

package service

import (
	"time"
)

func Service(args []string) {

	runProxy(args[:])
	time.Sleep(2 * time.Second)

}
