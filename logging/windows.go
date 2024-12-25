//go:build windows

package logging

import (
	"fmt"
	"golang.org/x/sys/windows/svc/eventlog"
	"myproxy/readconfig"
	"regexp"
	"strings"
)

var alreadyExists bool = false

func Printf(level string, format string, a ...any) (int, error) {
	var err error
	var loggerName string = "myproxy"
	var wlog *eventlog.Log

	// Log to local windows eventlog
	if !alreadyExists {
		err = eventlog.InstallAsEventCreate(loggerName, eventlog.Info|eventlog.Warning|eventlog.Error)
		if err != nil {
			alreadyExists, _ = regexp.MatchString(" registry key already exists", err.Error())
			if !alreadyExists {
				return 0, err
			}
		}
		alreadyExists = true
	}

	wlog, err = eventlog.Open(loggerName)
	if err != nil {
		return 0, err
	}

	message := fmt.Sprintf(format, a...)
	if level == "INFO" {
               switch {
                        case
                                strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
                                strings.ToUpper(readconfig.Config.Logging.Level) == "INFO",
				err = wlog.Info(100, "INFO: "+message)
                        default:
                }
	} else if level == "DEBUG" {
               switch {
                        case
                                strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
  				err = wlog.Info(700, "DEBUG: "+message)
                        default:
                }
	} else if level == "WARNING" {
               switch {
                        case
                                strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
                                strings.ToUpper(readconfig.Config.Logging.Level) == "INFO",
                                strings.ToUpper(readconfig.Config.Logging.Level) == "WARNING",
				err = wlog.Warning(200, "WARNING: "+message)
                        default:
                }
	} else if level == "ERROR" {
		err = wlog.Error(300, "ERROR: "+message)
	} else {
		err = wlog.Info(500, "UNKNONW: "+message)
	}
	wlog.Close()
	if err != nil {
		return 0, err
	} else {
		return len(message), err
	}
}
