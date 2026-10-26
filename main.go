package main

import (
	"fmt"
	"net/http"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

// sets up the keys and handlers without actually starting the server
func setupServer() error {
	//Create/open DB file
	db, err := sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()
	sqlStmt := `
    CREATE TABLE IF NOT EXISTS keys(
    	kid INTEGER PRIMARY KEY AUTOINCREMENT,
    	key BLOB NOT NULL,
    	exp INTEGER NOT NULL
	);
    `
	_, err = db.Exec(sqlStmt)
	if err != nil {
		fmt.Println(err)
	}

	//Make keys
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
