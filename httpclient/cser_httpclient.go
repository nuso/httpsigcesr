package httpclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"

	"github.com/nuso/httpsigcesr/digest"
	"github.com/nuso/httpsigcesr/signature"
)

var (
	signatureFields = []string{"@method", "@path", "origin-date", "signify-resource", "content-digest"}
)

type CserSignedClient struct {
	privateKey ed25519.PrivateKey
	publicKey  string
}

func NewCserSignedClient(publicKey string, privateKey ed25519.PrivateKey) HttpClient {
	return &CserSignedClient{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

func (csc *CserSignedClient) SendSignedRequest(c context.Context, method string, url string, body interface{}) (*http.Response, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader := bytes.NewReader(bodyBytes)
	req, err := http.NewRequestWithContext(c, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	// // digest is url-safe Base64-encoded without padding
	err = digest.AddDigest(req, digest.DigestSha256, bodyBytes, false)
	if err != nil {
		return nil, err
	}
	if len(bodyBytes) >= 0 {
		req.Header.Add("Content-Type", "application/json")
	}

	req.Header.Add("signify-resource", csc.publicKey)

	signatureData := signature.NewSignatureData(signatureFields, csc.publicKey, csc.privateKey)
	err = signatureData.SignRequest(req)

	client := &http.Client{}
	return client.Do(req)
}
