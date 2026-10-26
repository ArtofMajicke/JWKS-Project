package main

import (
	"encoding/json"
	"net/http"
	"time"
)

func jwksHandler(w http.ResponseWriter, r *http.Request) { // /.well-known/jwks.json
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jwks := JWKS{}

	now := time.Now().Unix()

	//If key is not expired, add it to the list of possible keys to send to the client, converting it to a JWK in the process
	rows, err = db.Exec("SELECT kid, key FROM keys WHERE exp > ?", now)
	if err != nil {
		fmt.Println(err)
	}
	defer rows.Close()
	for rows.Next() {
		var kid int
		var key string
		err = rows.Scan(&kid, &key)
		if err != nil {
			fmt.Println(err)
		}

		//deserialize key
		block, _ := pem.Decode(key)
		privateKeyImported, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
		rsaPrivateKey := privateKeyImported.(*rsa.PrivateKey)
		
		//add to jwks to send
		jwks.Keys = append(jwks.Keys, keyToJWK(rsaPrivateKey, kid))
	}
	if err = rows.Err(); err != nil {
		fmt.Println(err)
	}
	
	//send it
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
