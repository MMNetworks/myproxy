//go:build windows

// Package logging provides Windows-specific log output support for myproxy.
//
// It writes logging events to the Windows Event Log when the proxy is running
// on Windows-based systems.
package logging

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

var alreadyExists = false

func _systemLog(_ string, level string, format string, a ...any) (int, error) {
	const stdoutLog = "C:\\Temp\\myproxy_stdout.log"
	var length int
	var err error
	var loggerName = "myproxy"
	var wlog *eventlog.Log

	current.Mu.Lock()
	defer current.Mu.Unlock()
	inService, err := svc.IsWindowsService()
	if err == nil && inService && strings.ToUpper(current.logFilename) == "STDOUT" {
		// Cannot log to stdout from service
		current.logFilename = stdoutLog
	}

	message := fmt.Sprintf(format, a...)
	// Log to local windows eventlog
	if !alreadyExists {
		err = eventlog.InstallAsEventCreate(loggerName, eventlog.Info|eventlog.Warning|eventlog.Error)
		if err != nil {
			alreadyExists, _ = regexp.MatchString(" registry key already exists", err.Error())
			if !alreadyExists {
				var newlogFilename = "STDOUT"
				if inService {
					newlogFilename = stdoutLog
				}
				message := fmt.Sprintf("Printf: Cannot create eventlog: %v\n", err)
				_, _ = osPrintf(newlogFilename, "ERROR", "%s", message)
				message = fmt.Sprintf("Printf: switch to %s\n", newlogFilename)
				_, _ = osPrintf(newlogFilename, "INFO", "%s", message)
				current.logFilename = newlogFilename
				message = fmt.Sprintf(format, a...)
				_, _ = osPrintf(current.logFilename, level, "%s", message)
				return 0, err
			}
		}
		alreadyExists = true
	}

	wlog, err = eventlog.Open(loggerName)
	if err != nil {
		return 0, err
	}

	switch level {
	case "INFO":
		switch {
		case
			current.logLevel == "DEBUG",
			current.logLevel == "INFO":
			err = wlog.Info(100, "INFO: "+message)
			length = len("INFO: " + message)
		default:
		}
	case "DEBUG":
		switch {
		case
			current.logLevel == "DEBUG":
			err = wlog.Info(700, "DEBUG: "+message)
			length = len("DEBUG: " + message)
		default:
		}
	case "WARNING":
		switch {
		case
			current.logLevel == "DEBUG",
			current.logLevel == "INFO",
			current.logLevel == "WARNING":
			err = wlog.Warning(200, "WARNING: "+message)
			length = len("WARNING: " + message)
		default:
		}
	case "ERROR":
		err = wlog.Error(300, "ERROR: "+message)
		length = len("ERROR: " + message)
	case "ACCESS", "STARTLOG":
		err = wlog.Info(500, level+": "+message)
		length = len(level + ": " + message)
	case "TRACE":
		// Don't log trace to eventlog
	default:
		err = wlog.Info(500, "UNKNONW: "+message)
		length = len("UNKNOWN: " + message)
	}
	_ = wlog.Close()
	return length, err
}
