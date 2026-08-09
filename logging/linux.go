//go:build !windows

// Package logging provides Linux-specific log output support for myproxy.
//
// It writes logging events to the local syslog service when the proxy is
// running on Linux-based systems.
package logging

import (
	"fmt"
	"log/syslog"
)

func _systemLog(_ string, level string, format string, a ...any) (int, error) {
	var length int
	var err error

	current.Mu.Lock()
	defer current.Mu.Unlock()
	logLevel := current.logLevel
	message := fmt.Sprintf(format, a...)
	var sysLog *syslog.Writer
	// Log to local Unix syslog socket
	// Need to add option to change to udp,tcp, ...

	sysLog, err = syslog.Dial("", "/dev/log",
		syslog.LOG_WARNING|syslog.LOG_DAEMON, "myproxy")
	if err != nil {
		return 0, err
	}
	switch level {
	case "INFO":
		switch {
		case
			logLevel == "DEBUG",
			logLevel == "INFO":
			err = sysLog.Info("INFO: " + message)
			length = len("INFO: " + message)
		default:
		}
	case "DEBUG":
		switch {
		case
			logLevel == "DEBUG":
			err = sysLog.Debug("DEBUG: " + message)
			length = len("DEBUG: " + message)
		default:
		}
	case "WARNING":
		switch {
		case
			logLevel == "DEBUG",
			logLevel == "INFO",
			logLevel == "WARNING":
			err = sysLog.Warning("WARNING: " + message)
			length = len("WARNING: " + message)
		default:
		}
	case "ERROR":
		err = sysLog.Err("ERROR: " + message)
		length = len("ERROR: " + message)
	case "ACCESS", "STARTLOG":
		err = sysLog.Info(level + ": " + message)
		length = len(level + ": " + message)
	case "TRACE":
		// Don't log trace to syslog
	default:
		err = sysLog.Info("UNKNOWN:" + message)
		length = len("UNKNOWN: " + message)
	}
	_ = sysLog.Close()
	return length, err
}
