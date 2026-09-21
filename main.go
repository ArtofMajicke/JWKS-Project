package main

import (
	"fmt"
	"net/http"
)

func setupServer() error {
	err := initializeKeys()
	if err != nil {
		return err
	}

	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	return nil
}

func main() {
	err := setupServer()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Server running on http://localhost:8080")

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println(err)
	}
}
