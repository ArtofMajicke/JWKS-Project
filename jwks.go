package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"time"
)

func jwksHandler(w http.ResponseWriter, r *http.Request) { // /.well-known/jwks.json
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jwks := JWKS{
		Keys: []JWK{},
	}

	now := time.Now().Unix()

	//If key is not expired, add it to the list of possible keys to send to the client, converting it to a JWK in the process
	rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", now)
	if err != nil {
		log.Printf("Failed to retrieve key: %v", err)
		http.Error(w, "Failed to retrieve key", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var kid int
		var key []byte
		err = rows.Scan(&kid, &key)
		if err != nil {
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

		//add to jwks to send
		jwks.Keys = append(jwks.Keys, keyToJWK(rsaPrivateKey, kid))
	}
	if err = rows.Err(); err != nil {
		log.Printf("Failed to retrieve key: %v", err)
		http.Error(w, "Failed to retrieve key", http.StatusInternalServerError)
		return
	}

	//send it
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
