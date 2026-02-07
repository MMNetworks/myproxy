//go:build windows

package logging

import (
	"fmt"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"regexp"
	"strings"
)

var alreadyExists bool = false

func _systemLog(timeStamp string, level string, format string, a ...any) (int, error) {
	const stdoutLog string = "C:\\Temp\\myproxy_stdout.log"
	var length int = 0
	var err error = nil
	var loggerName string = "myproxy"
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
				osPrintf(newlogFilename, "ERROR", message)
				message = fmt.Sprintf("Printf: switch to %s\n", newlogFilename)
				osPrintf(newlogFilename, "INFO", message)
				current.logFilename = newlogFilename
				message = fmt.Sprintf(format, a...)
				osPrintf(current.logFilename, level, message)
				return 0, err
			}
		}
		alreadyExists = true
	}

	wlog, err = eventlog.Open(loggerName)
	if err != nil {
		return 0, err
	}

	if level == "INFO" {
		switch {
		case
			current.logLevel == "DEBUG",
			current.logLevel == "INFO":
			err = wlog.Info(100, "INFO: "+message)
			length = len("INFO: " + message)
		default:
		}
	} else if level == "DEBUG" {
		switch {
		case
			current.logLevel == "DEBUG":
			err = wlog.Info(700, "DEBUG: "+message)
			length = len("DEBUG: " + message)
		default:
		}
	} else if level == "WARNING" {
		switch {
		case
			current.logLevel == "DEBUG",
			current.logLevel == "INFO",
			current.logLevel == "WARNING":
			err = wlog.Warning(200, "WARNING: "+message)
			length = len("WARNING: " + message)
		default:
		}
	} else if level == "ERROR" {
		err = wlog.Error(300, "ERROR: "+message)
		length = len("ERROR: " + message)
	} else if level == "ACCESS" || level == "STARTLOG" {
		err = wlog.Info(500, level+": "+message)
		length = len(level + ": " + message)
	} else if level == "TRACE" {
		// Don't log trace to eventlog
	} else {
		err = wlog.Info(500, "UNKNONW: "+message)
		length = len("UNKNOWN: " + message)
	}
	wlog.Close()
	return length, err
}
