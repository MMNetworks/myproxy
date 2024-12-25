//go:build !windows

package logging

import (
	"fmt"
	"log/syslog"
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
		err = sysLog.Info(message)
	} else if level == "DEBUG" {
		err = sysLog.Debug(message)
	} else if level == "WARNING" {
		err = sysLog.Warning(message)
	} else if level == "ERROR" {
		err = sysLog.Err(message)
	} else {
		err = sysLog.Info(message)
	}
	sysLog.Close()
	return len(message),err
}

