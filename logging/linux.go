//go:build !windows

package logging

import (
	"fmt"
	"log/syslog"
	"myproxy/readconfig"
	"strings"
)

func Printf(level string, format string, a ...any) (int, error) {
	// Log to local Unix syslog socket 
	// Need to add option to change to udp,tcp, ...

	sysLog, err := syslog.Dial("", "/dev/log",
		syslog.LOG_WARNING|syslog.LOG_DAEMON, "myproxy")
	if err != nil {
		return 0,err
	} 
	message := fmt.Sprintf(format, a...)
	if level == "INFO" {
		switch {
			case 
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO":
				err = sysLog.Info("INFO: " + message)
			default:
		}
	} else if level == "DEBUG" {
		switch {
			case 
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG":
				err = sysLog.Debug("DEBUG: " + message)
			default:
		}
	} else if level == "WARNING" {
		switch {
			case 
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO",
				strings.ToUpper(readconfig.Config.Logging.Level) == "WARNING":
				err = sysLog.Warning("WARNING: " + message)
			default:
		}
	} else if level == "ERROR" {
		err = sysLog.Err("ERROR: " + message)
	} else {
		err = sysLog.Info("UNKNOWN:" + message)
	}
	sysLog.Close()
	return len(message),err
}

