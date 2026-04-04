// Create a 256 password hash
package main

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/term"
	"os"
)

func main() {
	fmt.Print("Enter Password: ")
	// #nosec G115 (CWE-190) -- save
	fd := int(os.Stdin.Fd())
	bytePassword, err := term.ReadPassword(fd)
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
