package main

import (
	"myproxy/logging"
)

const Version = "2.0.1"

func init() {
	logging.Printf("INFO", "main: Starting version: %s\n", Version)

}
