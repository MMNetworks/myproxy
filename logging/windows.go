//go:build windows

package logging

import (
	"os"
	"fmt"
	"golang.org/x/sys/windows/svc/eventlog"
	"myproxy/readconfig"
	"regexp"
	"strings"
	"time"
)

var alreadyExists bool = false

func Printf(level string, format string, a ...any) (int, error) {
	var length int = 0
	var err error = nil
	var loggerName string = "myproxy"
	var wlog *eventlog.Log

	message := fmt.Sprintf(format, a...)
	if strings.ToUpper(readconfig.Config.Logging.File) == "SYSLOG" || strings.ToUpper(readconfig.Config.Logging.File)  == "EVENTLOG" {
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

		if level == "INFO" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO":
				err = wlog.Info(100, "INFO: "+message)
				length = len("INFO: " + message)
			default:
			}
		} else if level == "DEBUG" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG":
  				err = wlog.Info(700, "DEBUG: "+message)
				length = len("DEBUG: " + message)
			default:
			}
		} else if level == "WARNING" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO",
				strings.ToUpper(readconfig.Config.Logging.Level) == "WARNING":
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
	} else if strings.ToUpper(readconfig.Config.Logging.File) != "STDOUT" {
		 var logFile *os.File
		// Log to local Unix file
		logFile, err = os.OpenFile(readconfig.Config.Logging.File, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
                if err != nil {
                       return 0, err
                }
		timeStamp := time.Now().Format(time.RFC1123)
 		if level == "INFO" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO":
				length, err = fmt.Fprintf(logFile,"%s INFO: %s", timeStamp, message)
			default:
			}
		} else if level == "DEBUG" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG":
				length, err = fmt.Fprintf(logFile,"%s DEBUG: %s", timeStamp, message)
			default:
			}
		} else if level == "WARNING" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO",
				strings.ToUpper(readconfig.Config.Logging.Level) == "WARNING":
				length, err = fmt.Fprintf(logFile,"%s WARNING: %s", timeStamp, message)
			default:
			}
		} else if level == "ERROR" {
			length, err = fmt.Fprintf(logFile,"%s ERROR: %s", timeStamp, message)
		} else {
			length, err = fmt.Fprintf(logFile,"%s UNKNOWN: %s", timeStamp, message)
		}
		logFile.Close()
	} else {
		// Log to stdout
		timeStamp := time.Now().Format(time.RFC1123)
		if level == "INFO" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO":
				length, err = fmt.Printf("%s INFO: %s", timeStamp, message)
			default:
			}
		} else if level == "DEBUG" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG":
				length, err = fmt.Printf("%s DEBUG: %s", timeStamp, message)
			default:
			}
		} else if level == "WARNING" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO",
				strings.ToUpper(readconfig.Config.Logging.Level) == "WARNING":
				length, err = fmt.Printf("%s WARNING: %s", timeStamp, message)
			default:
			}
		} else if level == "ERROR" {
			length, err = fmt.Printf("%s ERROR: %s", timeStamp, message)
		} else {
			length, err = fmt.Printf("%s UNKNOWN: %s", timeStamp, message)
		}
	}
	return length, err
}
