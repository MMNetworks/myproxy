//go:build !windows

package log

import "syscall"

const SIGUSR1 = syscall.SIGUSR1
