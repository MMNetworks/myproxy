//go:build windows

package logging

import (
	"regexp"
	"fmt"
	"golang.org/x/sys/windows/svc/eventlog"
)

var alreadyExists bool = false

func Printf(level string, format string, a ...any) (int, error) {
	var err error
	var loggerName string = "myproxy"
	var wlog *eventlog.Log

        // Log to local windows eventlog
        if ! alreadyExists {
                err = eventlog.InstallAsEventCreate(loggerName, eventlog.Info | eventlog.Warning | eventlog.Error)
                if err != nil {
                        alreadyExists, _ = regexp.MatchString(" registry key already exists",err.Error())
                        if ! alreadyExists {
                                return 0,err
                        }
                }
                alreadyExists = true
        }

	wlog, err = eventlog.Open(loggerName)
        if err != nil {
                return 0,err
        }
	
	message := fmt.Sprintf(format, a...)
	if level == "INFO" {
		err = wlog.Info(100,message)
	} else if level == "DEBUG" {
		err = wlog.Info(700,message)
	} else if level == "WARNING" {
		err = wlog.Warning(200,message)
	} else if level == "ERROR" {
		err = wlog.Error(300,message)
	} else {
		err = wlog.Info(500,message)
	}
	wlog.Close()
	if err != nil {
		return 0,err
	} else {
		return len(message),err
	}
}

