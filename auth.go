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

	if key == nil {
		http.Error(w, "No suitable key available", http.StatusInternalServerError)
		return
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.MapClaims{
			"sub": "test-user",
			"iat": now,
			"exp": key.ExpiresAt,
		},
	)
	token.Header["kid"] = key.Kid

	signedToken, err := token.SignedString(key.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(signedToken))
}
