package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
)

func main() {
	payload := `[{"source":"commit","token":"some_token","type":"some_type","url":"https://example.com/base-repo-url/"}]`
	kID := "bcb53661c06b4728e59d897fb6165d5c9cda0fd9cdf9d09ead458168deb7518c"
	kSig := "MEQCIQDaMKqrGnE27S0kgMrEK0eYBmyG0LeZismAEz/BgZyt7AIfXt9fErtRS4XaeSt/AO1RtBY66YcAdjxji410VQV4xg=="

	GITHUB_KEYS_URI := "https://api.github.com/meta/public_keys/secret_scanning"

	// Fetch the list of GitHub Public Keys
	req, err := http.NewRequest("GET", GITHUB_KEYS_URI, nil)
	if err != nil {
		fmt.Printf("Error preparing request: %s\n", err)
		os.Exit(1)
	}

	if len(os.Getenv("GITHUB_PRODUCTION_TOKEN")) > 0 {
		req.Header.Add("Authorization", "Bearer "+os.Getenv("GITHUB_PRODUCTION_TOKEN"))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("Error requesting GitHub signing keys: %s\n", err)
		os.Exit(2)
	}

	decoder := json.NewDecoder(resp.Body)
	var keys GitHubSigningKeys
	if err := decoder.Decode(&keys); err != nil {
		fmt.Printf("Error decoding GitHub signing key request: %s\n", err)
		os.Exit(3)
	}

	// Find the Key used to sign our webhook
	pubKey, err := func() (string, error) {
		for _, v := range keys.PublicKeys {
			if v.KeyIdentifier == kID {
				return v.Key, nil

			}
		}
		return "", errors.New("specified key was not found in GitHub key list")
	}()

	if err != nil {
		fmt.Printf("Error finding GitHub signing key: %s\n", err)
		os.Exit(4)
	}

	// Decode the Public Key
	block, _ := pem.Decode([]byte(pubKey))
	if block == nil {
		fmt.Println("Error parsing PEM block with GitHub public key")
		os.Exit(5)
	}

	// Create our ECDSA Public Key
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Printf("Error parsing DER encoded public key: %s\n", err)
		os.Exit(6)
	}

	// Because of documentation, we know it's a *ecdsa.PublicKey
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("GitHub key was not ECDSA, what are they doing?!")
		os.Exit(7)
	}

	// Parse the Webhook Signature
	parsedSig := asn1Signature{}
	asnSig, err := base64.StdEncoding.DecodeString(kSig)
	if err != nil {
		fmt.Printf("unable to base64 decode signature: %s\n", err)
		os.Exit(8)
	}
	rest, err := asn1.Unmarshal(asnSig, &parsedSig)
	if err != nil || len(rest) != 0 {
		fmt.Printf("Error unmarshalling asn.1 signature: %s\n", err)
		os.Exit(9)
	}

	// Verify the SHA256 encoded payload against the signature with GitHub's Key
	digest := sha256.Sum256([]byte(payload))
	keyOk := ecdsa.Verify(ecdsaKey, digest[:], parsedSig.R, parsedSig.S)

	if keyOk {
		fmt.Println("THE PAYLOAD IS GOOD!!")
	} else {
		fmt.Println("the payload is invalid :(")
		os.Exit(10)
	}
}

type GitHubSigningKeys struct {
	PublicKeys []struct {
		KeyIdentifier string `json:"key_identifier"`
		Key           string `json:"key"`
		IsCurrent     bool   `json:"is_current"`
	} `json:"public_keys"`
}

// asn1Signature is a struct for ASN.1 serializing/parsing signatures.
type asn1Signature struct {
	R *big.Int
	S *big.Int
}
