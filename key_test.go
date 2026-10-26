package main

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")

	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Exec(`
        CREATE TABLE keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    `)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("failed to close test database: %v", err)
		}
	})
}

type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, errors.New("forced error")
}

func TestGenerateKeyError(t *testing.T) {
	oldReader := rand.Reader
	rand.Reader = failingReader{}

	defer func() {
		rand.Reader = oldReader
	}()

	err := generateKey(time.Now().Unix())

	if err == nil {
		t.Fatal("expected generateKey to return an error")
	}
}

func TestInitializeKeys(t *testing.T) {
	setupTestDB(t)

	if err := initializeKeys(); err != nil {
		t.Fatal(err)
	}

	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}

	if count != 2 {
		t.Fatalf("expected 2 keys, got %d", count)
	}
}

func TestInitializeKeysError(t *testing.T) {
	setupTestDB(t)

	oldGenerateKeyFunc := generateKeyFunc
	generateKeyFunc = func(exp int64) error {
		return errors.New("forced key generation failure")
	}
	defer func() {
		generateKeyFunc = oldGenerateKeyFunc
	}()

	if err := initializeKeys(); err == nil {
		t.Fatal("expected initializeKeys to return an error")
	}
}
