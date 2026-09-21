package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"time"
)

type Key struct {
	Kid        string
	PrivateKey *rsa.PrivateKey
	ExpiresAt  int64
}

var keys []*Key

type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

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

func initializeKeys() error {
	now := time.Now()

	currentKey, err := generateKey(
		"current-key",
		now.Add(time.Hour).Unix(),
	)
	if err != nil {
		return err
	}

	expiredKey, err := generateKey(
		"expired-key",
		now.Add(-time.Hour).Unix(),
	)
	if err != nil {
		return err
	}

	keys = []*Key{currentKey, expiredKey}

	return nil
}

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
