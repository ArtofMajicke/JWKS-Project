package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB //declare db here so it's global
var dbPath = "./totally_not_my_privateKeys.db"
var serverMux *http.ServeMux

// sets up the keys and handlers without actually starting the server
func setupServer() error {
	//Create/open DB file
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	sqlStmt := `
    CREATE TABLE IF NOT EXISTS keys(
    	kid INTEGER PRIMARY KEY AUTOINCREMENT,
    	key BLOB NOT NULL,
    	exp INTEGER NOT NULL
	);
    `
	_, err = db.Exec(sqlStmt)
	if err != nil {
		return err
	}

	//Make keys
	err = initializeKeys()
	if err != nil {
		return err
	}

	serverMux = http.NewServeMux()
	serverMux.HandleFunc("/.well-known/jwks.json", jwksHandler)
	serverMux.HandleFunc("/auth", authHandler)

	return nil
}

func main() {
	err := setupServer()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Server running on http://localhost:8080")

	err = http.ListenAndServe(":8080", serverMux)
	if err != nil {
		fmt.Println(err)
	}
	db.Close()
}
