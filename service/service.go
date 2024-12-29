//go:build !windows

package service

import (
	"sync"
)

func Service(args []string) {

	runProxy(args[:])

	return
}
