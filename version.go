package main

import (
	"fmt"
	"time"
)

const Version = "2.5.0"

func init() {
	timeStamp := time.Now().Format(time.RFC1123)
	fmt.Printf("%s INFO: main: Starting version: %s\n", timeStamp, Version)

}
