package main

import (
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestSetupServer(t *testing.T) {
	dbPath = filepath.Join(t.TempDir(), "test.db")

	if err := setupServer(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("failed to close database: %v", err)
		}
	})

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count); err != nil {
		t.Fatal(err)
	}

	if count != 2 {
		t.Fatalf("expected 2 initialized keys, got %d", count)
	}

	if serverMux == nil {
		t.Fatal("expected server mux to be initialized")
	}
}
