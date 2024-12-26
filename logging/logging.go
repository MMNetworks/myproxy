package logging

import (
	"fmt"
	"myproxy/readconfig"
	"os"
	"strings"
	"time"
)

func osPrintf(level string, format string, a ...any) (int, error) {
	var length int = 0
	var err error = nil

	message := fmt.Sprintf(format, a...)
	if strings.ToUpper(readconfig.Config.Logging.File) != "STDOUT" {
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
				length, err = fmt.Fprintf(logFile, "%s INFO: %s", timeStamp, message)
			default:
			}
		} else if level == "DEBUG" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG":
				length, err = fmt.Fprintf(logFile, "%s DEBUG: %s", timeStamp, message)
			default:
			}
		} else if level == "WARNING" {
			switch {
			case
				strings.ToUpper(readconfig.Config.Logging.Level) == "DEBUG",
				strings.ToUpper(readconfig.Config.Logging.Level) == "INFO",
				strings.ToUpper(readconfig.Config.Logging.Level) == "WARNING":
				length, err = fmt.Fprintf(logFile, "%s WARNING: %s", timeStamp, message)
			default:
			}
		} else if level == "ERROR" {
			length, err = fmt.Fprintf(logFile, "%s ERROR: %s", timeStamp, message)
		} else {
			length, err = fmt.Fprintf(logFile, "%s UNKNOWN: %s", timeStamp, message)
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