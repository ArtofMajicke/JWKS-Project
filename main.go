package main

import (
	"fmt"
	"net/http"
)

func main() {
	err := initializeKeys() //create the keys for signing and verifying JWTs
	if err != nil {         //show if there is an error
		fmt.Println(err)
		return
	}

	//direct requests to the appropriate handler functions
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("Server running on http://localhost:8080") //Show the server is running
	err = http.ListenAndServe(":8080", nil)                //begin listening for requests
	if err != nil {
		fmt.Println(err)
	}
}
