// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package service

import (
	"flag"
	"fmt"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"log"
	"myproxy/logging"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var svcName = "myproxy"

func Service(args []string) {
	var err error
	var action string
	var configFilename string
	var cF string
	var fS os.FileInfo
	var state svc.State

	if len(args) == 0 {
		log.Printf("ERROR: Service: missing argument list\n")
		os.Exit(1)
	}
	CommandLine := flag.NewFlagSet("Service", flag.ExitOnError)

	CommandLine.StringVar(&action, "a", "none", "Windows service action to run. Options are install, start, stop, pause, continue, status and remove")
	CommandLine.StringVar(&configFilename, "c", "myproxy.yaml", "Specify configuration filename.")

	CommandLine.Parse(args[1:])

	cF, err = filepath.Abs(configFilename)
	if err != nil {
		log.Printf("ERROR: Service: cannot determine absolute file path of configuration file: %s\n", configFilename)
		os.Exit(1)
	}
	fS, err = os.Stat(cF)
	if err == nil {
		if fS.Mode().IsDir() {
			log.Printf("ERROR: Service: configuration file %s is a directory\n", configFilename)
			os.Exit(1)
		}
	}
	configFilename = cF

	inService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("ERROR: Service: failed to determine if we are running in service: %v\n", err)
	} else {
		log.Printf("DEBUG: Service: inService: %t\n", inService)
	}
	if inService {
		runService(svcName)
		return
	}

	cmd := strings.ToLower(action)

	log.Printf("INFO: Service: run command %s\n", cmd)
	switch cmd {
	case "install":
		err = installService(svcName, "myproxy Service", configFilename)
	case "remove":
		err = removeService(svcName)
	case "start":
		err = startService(svcName, configFilename)
	case "stop":
		err, state = controlService(svcName, svc.Stop, svc.Stopped)
	case "pause":
		err, state = controlService(svcName, svc.Pause, svc.Paused)
	case "continue":
		err, state = controlService(svcName, svc.Continue, svc.Running)
	case "status":
		err, state = controlService(svcName, svc.Interrogate, 0)
	default:
		log.Printf("INFO: Service: run interactive\n")
		runProxy(args[:])
	}
	if err != nil {
		log.Printf("ERROR: Service: failed to %s %s: %v\n", cmd, svcName, err)
	} else {
		log.Printf("INFO: Service: status %s\n", stateName(state))
	}
	return
}

func exePath() (string, error) {
	prog := os.Args[0]
	p, err := filepath.Abs(prog)
	if err != nil {
		return "", err
	}
	pe := p
	if filepath.Ext(pe) == "" {
		pe += ".exe"
		fi, err := os.Stat(pe)
		if err == nil {
			if !fi.Mode().IsDir() {
				return pe, nil
			}
			err = fmt.Errorf("%s is directory", pe)
		}
	}
	fi, err := os.Stat(p)
	if err == nil {
		if !fi.Mode().IsDir() {
			return p, nil
		}
		err = fmt.Errorf("%s is directory", p)
	}
	return "", err
}

func installService(name, desc string, configFile string) error {
	exepath, err := exePath()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", name)
	}
	s, err = m.CreateService(name, exepath, mgr.Config{DisplayName: desc}, "-c", configFile)
	if err != nil {
		return err
	}
	defer s.Close()
	return nil
}

func removeService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %s is not installed", name)
	}
	defer s.Close()
	err = s.Delete()
	if err != nil {
		return err
	}
	return nil
}

func startService(name string, configFile string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer s.Close()
	logging.Printf("INFO", "startService: starting %s service with config file: %s\n", name, configFile)
	err = s.Start("-c", configFile)
	if err != nil {
		return fmt.Errorf("could not start service: %v", err)
	}
	logging.Printf("INFO", "startService: started %s service\n", name)
	return nil
}

func controlService(name string, c svc.Cmd, to svc.State) (error, svc.State) {
	m, err := mgr.Connect()
	if err != nil {
		return err, 0
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err), 0
	}
	defer s.Close()
	status, err := s.Control(c)
	if err != nil {
		return fmt.Errorf("could not send control=%d: %v", c, err), 0
	}
	timeout := time.Now().Add(10 * time.Second)
	for c != svc.Interrogate && status.State != to {
		if timeout.Before(time.Now()) {
			return fmt.Errorf("timeout waiting for service to go to state=%d", to), 0
		}
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("could not retrieve service status: %v", err), 0
		}
	}
	return err, status.State
}

func runService(name string) {
	var err error

	logging.Printf("INFO", "runService: starting %s service\n", name)
	run := svc.Run
	err = run(name, &myproxyService{})
	if err != nil {
		logging.Printf("ERROR", "runService: %s service failed: %v\n", name, err)
		return
	}
	logging.Printf("INFO", "runService: %s service stopped\n", name)
}

type myproxyService struct{}

func (m *myproxyService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}

	if len(args) > 0 {
		logging.Printf("DEBUG", "Execute: service args: %s\n", strings.Join(args[:], ","))
		go runProxy(args[:])
		logging.Printf("DEBUG", "Execute: run proxy\n")
	} else {
		logging.Printf("DEBUG", "Execute: no service args\n")
		var largs []string
		largs = []string{"myproxy"}
		runProxy(largs)
		logging.Printf("DEBUG", "Execute: run proxy\n")
	}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
			default:
				logging.Printf("ERROR", "Execute: unexpected control request #%d", c)
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return false, 0
}

func stateName(state svc.State) string {
	switch {
	case state == svc.Stopped:
		return "Stopped"
	case state == svc.StartPending:
		return "StartPending"
	case state == svc.StopPending:
		return "StopPending"
	case state == svc.Running:
		return "Running"
	case state == svc.ContinuePending:
		return "ContinuePending"
	case state == svc.PausePending:
		return "PausePending"
	case state == svc.Paused:
		return "Paused"
	default:
		return "Default"
	}

}
