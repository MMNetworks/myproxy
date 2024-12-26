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

	hash := sha256.New()
	hash.Write(bytePassword)
	hashSum := hash.Sum(nil)
	// fmt.Println(password)
	fmt.Printf("\n%x\n", hashSum)
}
