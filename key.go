package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"time"
)

// RSA Key for the server to keep
type Key struct {
	Kid        string
	PrivateKey *rsa.PrivateKey
	ExpiresAt  int64
}

// Slice of all the keys
var keys []*Key

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
func generateKey(kid string, expiresAt int64) (*Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &Key{
		Kid:        kid,
		PrivateKey: privateKey,
		ExpiresAt:  expiresAt,
	}, nil
}

// used for testing purposes to override the key generation function
var generateKeyFunc = generateKey

// Make a unexpired key and an expired key for proof of concept
func initializeKeys() error {
	now := time.Now()

	//unexpired key has expiry set one hour from starting up the server
	currentKey, err := generateKeyFunc(
		"current-key",
		now.Add(time.Hour).Unix(),
	)
	if err != nil {
		return err
	}

	//expired key has expiry set one hour before starting up the server
	expiredKey, err := generateKeyFunc(
		"expired-key",
		now.Add(-time.Hour).Unix(),
	)
	if err != nil {
		return err
	}

	//add them both to the keys slice
	keys = []*Key{currentKey, expiredKey}

	return nil
}

// Takes an RSA key and gathers the correct information to make a JWK to send to the client
func keyToJWK(key *Key) JWK {
	n := base64.RawURLEncoding.EncodeToString(key.PrivateKey.N.Bytes())

	eBytes := []byte{
		byte(key.PrivateKey.E >> 16),
		byte(key.PrivateKey.E >> 8),
		byte(key.PrivateKey.E),
	}

	return JWK{
		Kty: "RSA",
		N:   n,
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
		Alg: "RS256",
		Use: "sig",
		Kid: key.Kid,
	}
}
