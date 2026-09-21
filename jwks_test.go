package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJWKSHandler(t *testing.T) {
	err := initializeKeys()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	jwksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var jwks JWKS

	err = json.NewDecoder(rec.Body).Decode(&jwks)
	if err != nil {
		t.Fatal(err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 unexpired key, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].Kid != "current-key" {
		t.Fatalf("expected current-key, got %s", jwks.Keys[0].Kid)
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
