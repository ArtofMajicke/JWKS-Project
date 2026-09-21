package main

import (
	"encoding/json"
	"net/http"
	"time"
)

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jwks := JWKS{}

	now := time.Now().Unix()

	for _, key := range keys {
		if key.ExpiresAt > now {
			jwks.Keys = append(jwks.Keys, keyToJWK(key))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
