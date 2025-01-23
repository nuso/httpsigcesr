package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"

	"github.com/nuso/httpsigcesr/cesr"
)

func savePrivateKeyToFile(privateKey ed25519.PrivateKey, filename string) error {
	// Encode private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: privateKey,
	})

	// Write PEM to file
	return os.WriteFile(filename, privateKeyPEM, 0600)
}

func main() {
	// Generate a new Ed25519 key pair
	// The public key will be CESR-encoded with the "B" prefix
	// The CESR-encoded public key will be used to identify you as an API caller
	// The private key will be used to sign messages

	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	AIDforIdentifyingYouAsAPICaller := cesr.Encode(pubKey, "B")
	err := os.WriteFile("pubkey.txt", []byte(AIDforIdentifyingYouAsAPICaller), 0644)
	if err != nil {
		panic(err)
	}

	err = savePrivateKeyToFile(privKey, "privkey.pem")
	if err != nil {
		panic(err)
	}

	print("Public key saved to pubkey.txt\n")
	print("Private key saved to privkey.pem\n")

}
