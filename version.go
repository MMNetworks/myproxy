package main

import (
	"fmt"
	"time"
	"myproxy/service"
)

func init() {
	timeStamp := time.Now().Format(time.RFC1123)
	fmt.Printf("%s INFO: main: Starting version: %s\n", timeStamp, service.Version)

}
