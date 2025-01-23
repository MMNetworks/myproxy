package logging

import (
	"fmt"
	"myproxy/readconfig"
	"os"
	"strings"
	"time"
	"runtime"
)

func GetFunctionName() string {
        pc, _, _, _ := runtime.Caller(1)
        fn := runtime.FuncForPC(pc)
        return fn.Name()
}

func osPrintf(logFilename string, level string, format string, a ...any) (int, error) {
	var length int = 0
	var err error = nil
	var logLevel string = "DEBUG"
	var logTrace bool = false

	if readconfig.Config != nil {
		logLevel = strings.ToUpper(readconfig.Config.Logging.Level)
		logTrace = readconfig.Config.Logging.Trace
	}

	message := fmt.Sprintf(format, a...)
	if strings.ToUpper(logFilename) != "STDOUT" && logFilename != "" {
		var logFile *os.File
		// Log to local Unix file
		logFile, err = os.OpenFile(logFilename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return 0, err
		}
		timeStamp := time.Now().Format(time.RFC1123)
		if level == "INFO" {
			switch {
			case
				logLevel == "DEBUG",
				logLevel == "INFO":
				length, err = fmt.Fprintf(logFile, "%s INFO: %s", timeStamp, message)
			default:
			}
		} else if level == "DEBUG" {
			switch {
			case
				logLevel == "DEBUG":
				length, err = fmt.Fprintf(logFile, "%s DEBUG: %s", timeStamp, message)
			default:
			}
		} else if level == "WARNING" {
			switch {
			case
				logLevel == "DEBUG",
				logLevel == "INFO",
				logLevel == "WARNING":
				length, err = fmt.Fprintf(logFile, "%s WARNING: %s", timeStamp, message)
			default:
			}
		} else if level == "ERROR" {
			length, err = fmt.Fprintf(logFile, "%s ERROR: %s", timeStamp, message)
		} else if level == "ACCESS" {
			length, err = fmt.Fprintf(logFile, "%s ACCESS: %s", timeStamp, message)
		} else if level == "TRACE" {
			if logTrace {
				length, err = fmt.Printf("%s TRACE: %s", timeStamp, message)
			}
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
				logLevel == "DEBUG",
				logLevel == "INFO":
				length, err = fmt.Printf("%s INFO: %s", timeStamp, message)
			default:
			}
		} else if level == "DEBUG" {
			switch {
			case
				logLevel == "DEBUG":
				length, err = fmt.Printf("%s DEBUG: %s", timeStamp, message)
			default:
			}
		} else if level == "WARNING" {
			switch {
			case
				logLevel == "DEBUG",
				logLevel == "INFO",
				logLevel == "WARNING":
				length, err = fmt.Printf("%s WARNING: %s", timeStamp, message)
			default:
			}
		} else if level == "ERROR" {
			length, err = fmt.Printf("%s ERROR: %s", timeStamp, message)
		} else if level == "ACCESS" {
			length, err = fmt.Printf("%s ACCESS: %s", timeStamp, message)
		} else if level == "TRACE" {
			if logTrace {
				length, err = fmt.Printf("%s TRACE: %s", timeStamp, message)
			}
		} else {
			length, err = fmt.Printf("%s UNKNOWN: %s", level, timeStamp, message)
		}
	}
	return length, err
}
