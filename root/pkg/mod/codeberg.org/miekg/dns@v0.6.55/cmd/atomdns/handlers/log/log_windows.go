//go:build windows

package log

import "os"

var SIGUSR1 = os.Interrupt
