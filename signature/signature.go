package signature

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nuso/httpsigcesr/cesr"
)

type SignatureData struct {
	created         int64
	signatureFields []string
	privateKey      ed25519.PrivateKey
	publicKey       string
}

func NewSignatureData(fields []string, publicKey string, privateKey ed25519.PrivateKey) *SignatureData {
	return &SignatureData{
		created:         time.Now().UTC().Unix(),
		signatureFields: fields,
		publicKey:       publicKey,
		privateKey:      privateKey,
	}
}

func (sd *SignatureData) SignatureInput() string {
	fieldString := ""
	for _, field := range sd.signatureFields {
		if fieldString == "" {
			fieldString = fmt.Sprintf("\"%s\"", field)
		} else {
			fieldString = fmt.Sprintf("%s \"%s\"", fieldString, field)
		}
	}
	return fmt.Sprintf("(%s);created=%d;keyid=\"%s\";alg=\"%s\"", fieldString, sd.created, sd.publicKey, "ed25519")
}

func (sd *SignatureData) SignatureBase(r *http.Request) (string, error) {
	fieldString := ""
	for _, field := range sd.signatureFields {
		value, err := sd.evaluateField(field, r)
		if err != nil {
			return "", err
		}
		if fieldString == "" {
			fieldString = fmt.Sprintf("\"%s\": %s", field, value)
		} else {
			fieldString = fmt.Sprintf("%s\n\"%s\": %s", fieldString, field, value)
		}
	}
	if fieldString != "" {
		fieldString += "\n"
	}
	fieldString += fmt.Sprintf("\"@signature-params\": %s", sd.SignatureInput())
	return fieldString, nil
}

func (sd *SignatureData) SignRequest(r *http.Request) error {
	originDate := time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00")
	r.Header.Add("origin-date", originDate)

	s, err := sd.SignatureBase(r)
	if err != nil {
		return err
	}

	signatureInput := sd.SignatureInput()
	signature := ed25519.Sign(sd.privateKey, []byte(s))
	signatureCESR := cesr.Encode(signature, "0B")

	r.Header.Add("signature-input", fmt.Sprintf("signify=%s", signatureInput))
	r.Header.Add("signature", fmt.Sprintf("indexed=\"?0\";signify=\"%s\"", signatureCESR))

	return nil
}

func (sd *SignatureData) evaluateField(field string, r *http.Request) (string, error) {
	switch field {
	case "@method":
		return r.Method, nil
	case "@path":
		return r.URL.Path, nil
	case "@target-uri":
		return r.URL.RequestURI(), nil
	case "@authority":
		return r.URL.Host, nil
	case "@scheme":
		return r.URL.Scheme, nil
	case "@request-target":
		if len(r.URL.RawQuery) == 0 {
			return r.URL.RawPath, nil
		} else {
			return fmt.Sprintf("%s?%s", r.URL.RawPath, r.URL.RawQuery), nil
		}
	case "@query":
		if len(r.URL.RawQuery) == 0 {
			return "", nil
		}
		return fmt.Sprintf("?%s", r.URL.RawQuery), nil
	default:
		if strings.HasPrefix(field, "@") {
			return "", fmt.Errorf("unknown field %s", field)
		}
		return r.Header.Get(field), nil
	}
}
