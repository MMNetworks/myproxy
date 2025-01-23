package main

import (
	"myproxy/service"
	"os"
)

func main() {

	service.Service(os.Args[:])

}
