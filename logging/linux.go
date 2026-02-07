//go:build !windows

package logging

import (
	"fmt"
	"log/syslog"
)

func _systemLog(timeStamp string, level string, format string, a ...any) (int, error) {
	var length int = 0
	var err error = nil

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
	if level == "INFO" {
		switch {
		case
			logLevel == "DEBUG",
			logLevel == "INFO":
			err = sysLog.Info("INFO: " + message)
			length = len("INFO: " + message)
		default:
		}
	} else if level == "DEBUG" {
		switch {
		case
			logLevel == "DEBUG":
			err = sysLog.Debug("DEBUG: " + message)
			length = len("DEBUG: " + message)
		default:
		}
	} else if level == "WARNING" {
		switch {
		case
			logLevel == "DEBUG",
			logLevel == "INFO",
			logLevel == "WARNING":
			err = sysLog.Warning("WARNING: " + message)
			length = len("WARNING: " + message)
		default:
		}
	} else if level == "ERROR" {
		err = sysLog.Err("ERROR: " + message)
		length = len("ERROR: " + message)
	} else if level == "ACCESS" || level == "STARTLOG" {
		err = sysLog.Info(level + ": " + message)
		length = len(level + ": " + message)
	} else if level == "TRACE" {
		// Don't log trace to syslog
	} else {
		err = sysLog.Info("UNKNOWN:" + message)
		length = len("UNKNOWN: " + message)
	}
	sysLog.Close()
	return length, err
}
