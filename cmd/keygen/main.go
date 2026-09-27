// Command keygen creates a high-entropy API key and its configuration digest.
// Run it locally and store the plaintext key in a secret manager, never Git.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		fmt.Fprintln(os.Stderr, "generate API key:", err)
		os.Exit(1)
	}

	plaintext := base64.RawURLEncoding.EncodeToString(random)
	digest := sha256.Sum256([]byte(plaintext))
	fmt.Println("API key (store securely; shown once):", plaintext)
	fmt.Println("SHA-256 digest (put this in YAML):", hex.EncodeToString(digest[:]))
}
