package main

import (
	"fmt"
	"myproxy/service"
	"time"
)

func init() {
	timeStamp := time.Now().Format(time.RFC1123)
	fmt.Printf("%s INFO: main: Starting version: %s\n", timeStamp, service.Version)

}
