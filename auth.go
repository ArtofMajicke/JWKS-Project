package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func authHandler(w http.ResponseWriter, r *http.Request) { // /auth
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var kid int
	var key []byte
	var exp int64
	var err error
	now := time.Now().Unix()

	//Looks for expired keys if query asked for it, otherwise looks for unexpired keys.
	if r.URL.Query().Has("expired") { //FIXME also like couldn't I just use a bool and half this code
		err = db.QueryRow(
			"SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1",
			now,
		).Scan(&kid, &key, &exp)

	} else {
		err = db.QueryRow(
			"SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1",
			now,
		).Scan(&kid, &key, &exp)
	}

	if errors.Is(err, sql.ErrNoRows) { // If no key is found returns an error
		http.Error(w, "No suitable key available", http.StatusInternalServerError)
		return
	} else if err != nil {
		log.Printf("Failed to retrieve key: %v", err)
		http.Error(w, "Failed to retrieve key", http.StatusInternalServerError)
		return
	}

	//deserialize key
	block, _ := pem.Decode(key)
	if block == nil {
		http.Error(w, "Invalid stored key", http.StatusInternalServerError)
		return
	}
	privateKeyImported, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, "Invalid stored key", http.StatusInternalServerError)
		return
	}
	rsaPrivateKey, ok := privateKeyImported.(*rsa.PrivateKey)
	if !ok {
		http.Error(w, "Stored key is not RSA", http.StatusInternalServerError)
		return
	}

	KID := strconv.Itoa(kid)

	//Creates a JWT token with the selected key
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.MapClaims{
			"sub": "test-user",
			"iat": now,
			"exp": exp,
		},
	)
	token.Header["kid"] = KID

	//Signs the token with the selected key
	signedToken, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	//sends the signed token to the client
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(signedToken))
}
