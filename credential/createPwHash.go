package main

import (
	"syscall"
	"crypto/sha256"
	"fmt"
        "golang.org/x/term"
)

func main() {
	fmt.Print("Enter Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return 
	}
	// password := string(bytePassword)

	h := sha256.New()
	h.Write(bytePassword)
	bs := h.Sum(nil)
	//fmt.Println(password)
	fmt.Printf("\n%x\n", bs)
}
