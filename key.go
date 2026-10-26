package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strconv"
	"time"
)

// Data about the keys that JSON sends to clients
type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

// Slice of all the acceptable keys (not expired)
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Use random number to make an RSA key
func generateKey(expiresAt int64) error {
	//make the key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	//serialize it
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	//add to the db
	_, err = db.Exec("INSERT INTO keys(key, exp) VALUES(?, ?)", privatePEM, expiresAt)
	if err != nil {
		return err
	}

	return nil
}

// used for testing purposes to override the key generation function
var generateKeyFunc = generateKey

// Make a unexpired key and an expired key for proof of concept
func initializeKeys() error {
	now := time.Now()

	//unexpired key has expiry set one hour from starting up the server
	err := generateKeyFunc(now.Add(time.Hour).Unix())
	if err != nil {
		return err
	}

	//expired key has expiry set one hour before starting up the server
	err = generateKeyFunc(now.Add(-time.Hour).Unix())
	if err != nil {
		return err
	}

	return nil
}

// Takes an RSA key and gathers the correct information to make a JWK to send to the client
func keyToJWK(PrivateKey *rsa.PrivateKey, kid int) JWK {
	//convert kid to string for JWK
	KID := strconv.Itoa(kid)

	n := base64.RawURLEncoding.EncodeToString(PrivateKey.N.Bytes())

	eBytes := []byte{
		byte(PrivateKey.E >> 16),
		byte(PrivateKey.E >> 8),
		byte(PrivateKey.E),
	}

	return JWK{
		Kty: "RSA",
		N:   n,
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
		Alg: "RS256",
		Use: "sig",
		Kid: KID,
	}
}
