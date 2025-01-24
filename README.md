# httpsigcesr
signing http requests with cesr encoded signature

run the main to generate a public/private key pair

example usage:

```go
package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"github.com/nuso/httpsigcesr/httpclient"
	"os"
)

func readPemFile(fileName string) ([]byte, error) {

	// Step 1: Read the file contents
	pemData, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	// Step 2: Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		fmt.Println("Failed to parse PEM block")
		os.Exit(1)
	}
	return block.Bytes, nil
}

type ExampleRequest struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

func main() {
	//read PEM file from disk
	privKey, err := readPemFile("privkey.pem")
	if err != nil {
		fmt.Println("Error reading PEM file")
		os.Exit(1)
	}
	publicKeyBytes, err := os.ReadFile("pubkey.txt")
	if err != nil {
		fmt.Println("Error reading public key file")
		os.Exit(1)
	}
	publicKey := string(publicKeyBytes)

	client := httpclient.NewCserSignedClient(publicKey, privKey)
	req := ExampleRequest{
		Id:   1,
		Name: "John Doe",
	}
	client.SendSignedRequest(context.Background(), "POST", "http://google.com", req)

}
```


