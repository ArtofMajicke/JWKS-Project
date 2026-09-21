package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var key *Key
	now := time.Now().Unix()

	//Looks for expired keys if query asked for it, otherwise looks for unexpired keys.
	if r.URL.Query().Has("expired") {
		for _, candidate := range keys {
			if candidate.ExpiresAt <= now {
				key = candidate
				break
			}
		}
	} else {
		for _, candidate := range keys {
			if candidate.ExpiresAt > now {
				key = candidate
				break
			}
		}
	}

	// If no key is found, for instance both have expired and client requested unexpired keys, returns an error
	if key == nil {
		http.Error(w, "No suitable key available", http.StatusInternalServerError)
		return
	}

	//Creates a JWT token with the selected key
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.MapClaims{
			"sub": "test-user",
			"iat": now,
			"exp": key.ExpiresAt,
		},
	)
	token.Header["kid"] = key.Kid

	//Signs the token with the selected key
	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	//sends the signed token to the client
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(signedToken))
}
