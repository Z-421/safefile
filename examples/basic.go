package main

import (
	"fmt"
	"os"

	"github.com/Z-421/safefile/safefile"
)

func main() {
	inputPath := "example.txt"
	enctyptedPath := "example.enc"
	decryptedPath := "example_decrypted.txt"
	password := []byte("mypass")

	err := safefile.EncryptAndSaveFile(inputPath, enctyptedPath, password)
	if err != nil {
		fmt.Println("Encryption failed: ", err)
		return
	}
	fmt.Println("File encrypted successfuly")
	err = safefile.DecryptAndSaveFile(enctyptedPath, decryptedPath, password)
	if err != nil {
		fmt.Println("Decryption failed: ", err)
		return
	}
	fmt.Println("File decrypted successfuly")

	data, _ := os.ReadFile(decryptedPath)
	fmt.Println("Decrypted content: ", string(data))
}
