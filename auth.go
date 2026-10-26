package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func authHandler(w http.ResponseWriter, r *http.Request) { // /auth
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var kid int64
	var key string
	var exp int64
	now := time.Now().Unix()

	//Looks for expired keys if query asked for it, otherwise looks for unexpired keys.
	if r.URL.Query().Has("expired") { //FIXME also like couldn't I just use a bool and half this code
		err := db.QueryRow(
			"SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1",
			now,
		).Scan(&kid, &key, &exp)

	} else {
		err := db.QueryRow(
			"SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1",
			now,
		).Scan(&kid, &key, &exp)
	}

	if errors.Is(err, sql.ErrNoRows) { // If no key is found returns an error
		http.Error(w, "No suitable key available", http.StatusInternalServerError)
		return
	} else if err != nil {
		fmt.Println(err)
	}

	//Creates a JWT token with the selected key
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.MapClaims{
			"sub": "test-user",
			"iat": now,
			"exp": exp,
		},
	)
	token.Header["kid"] = kid

	//Signs the token with the selected key
	signedToken, err := token.SignedString(key)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	//sends the signed token to the client
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(signedToken))
}
