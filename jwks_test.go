package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestJWKSHandler(t *testing.T) {
	setupTestDB(t)

	if err := initializeKeys(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	)
	rec := httptest.NewRecorder()

	jwksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s",
			rec.Code, rec.Body.String())
	}

	var jwks JWKS
	if err := json.NewDecoder(rec.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 unexpired key, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].Kid != "1" {
		t.Fatalf("expected kid 1, got %s", jwks.Keys[0].Kid)
	}
}

func TestJWKSHandlerWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	jwksHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rec.Code)
	}
}

func TestJWKSHandlerEmptyDB(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	)
	rec := httptest.NewRecorder()

	jwksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s",
			rec.Code, rec.Body.String())
	}

	var jwks JWKS
	if err := json.NewDecoder(rec.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}

	if len(jwks.Keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(jwks.Keys))
	}
}

func TestJWKSHandlerDatabaseError(t *testing.T) {
	setupTestDB(t)

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(
		http.MethodGet, "/.well-known/jwks.json", nil,
	)
	rec := httptest.NewRecorder()

	jwksHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}
}
