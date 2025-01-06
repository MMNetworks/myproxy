//go:build windows

package logging

import (
	"fmt"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"myproxy/readconfig"
	"regexp"
	"strings"
)

var alreadyExists bool = false

func Printf(level string, format string, a ...any) (int, error) {
	const stdoutLog string = "C:\\Temp\\myproxy_stdout.log"
	var length int = 0
	var err error = nil
	var logFilename string = "STDOUT"
	var logLevel string = "DEBUG"
	var loggerName string = "myproxy"
	var wlog *eventlog.Log

	if readconfig.Config != nil {
		logFilename = readconfig.Config.Logging.File
		logLevel = strings.ToUpper(readconfig.Config.Logging.Level)
	}

	inService, err := svc.IsWindowsService()
	if err == nil && inService && logFilename == "STDOUT" {
		// Cannot log to stdout from service
		logFilename = stdoutLog
	}

	message := fmt.Sprintf(format, a...)
	if logFilename == "SYSLOG" || logFilename == "EVENTLOG" {
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
					osPrintf(newlogFilename,"ERROR","Printf: Cannot create eventlog: %v\n",err) 
					osPrintf(newlogFilename,"INFO","Printf: switch to %s\n",newlogFilename) 
					if readconfig.Config != nil {
				                readconfig.Config.Logging.File = newlogFilename
					}
					osPrintf(logFilename, level, format, a...)
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
				logLevel == "DEBUG",
				logLevel == "INFO":
				err = wlog.Info(100, "INFO: "+message)
				length = len("INFO: " + message)
			default:
			}
		} else if level == "DEBUG" {
			switch {
			case
				logLevel == "DEBUG":
				err = wlog.Info(700, "DEBUG: "+message)
				length = len("DEBUG: " + message)
			default:
			}
		} else if level == "WARNING" {
			switch {
			case
				logLevel == "DEBUG",
				logLevel == "INFO",
				logLevel == "WARNING":
				err = wlog.Warning(200, "WARNING: "+message)
				length = len("WARNING: " + message)
			default:
			}
		} else if level == "ERROR" {
			err = wlog.Error(300, "ERROR: "+message)
			length = len("ERROR: " + message)
		} else {
			err = wlog.Info(500, "UNKNONW: "+message)
			length = len("UNKNOWN: " + message)
		}
		wlog.Close()
	} else {
		length, err = osPrintf(logFilename, level, format, a...)
	}
	return length, err
}
