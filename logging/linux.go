//go:build !windows

package logging

import (
	"fmt"
	"log/syslog"
	"myproxy/readconfig"
	"strings"
)

func Printf(level string, format string, a ...any) (int, error) {
	var length int = 0
	var err error = nil

	message := fmt.Sprintf(format, a...)
	if strings.ToUpper(readconfig.Config.Logging.File) == "SYSLOG" || strings.ToUpper(readconfig.Config.Logging.File) == "EVENTLOG" {
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
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO":
				err = sysLog.Info("INFO: " + message)
				length = len("INFO: " + message)
			default:
			}
		} else if level == "DEBUG" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG":
				err = sysLog.Debug("DEBUG: " + message)
				length = len("DEBUG: " + message)
			default:
			}
		} else if level == "WARNING" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO",
				strings.ToUpper(readconfig.Config.Logging.Level) == "WARNING":
				err = sysLog.Warning("WARNING: " + message)
				length = len("WARNING: " + message)
			default:
			}
		} else if level == "ERROR" {
			err = sysLog.Err("ERROR: " + message)
			length = len("ERROR: " + message)
		} else {
			err = sysLog.Info("UNKNOWN:" + message)
			length = len("UNKNOWN: " + message)
		}
		sysLog.Close()
	} else {
		length, err = osPrintf(level, format, a...)
	}
	return length, err
}
