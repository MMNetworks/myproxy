package main

import (
	"myproxy/logging"
)

const Version = "1.5"

func init() {
	logging.Printf("INFO", "main: Starting version: %s\n", Version)

}
