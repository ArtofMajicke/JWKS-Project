package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestAuthHandler(t *testing.T) {
	err := initializeKeys()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()

	authHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	tokenString := rec.Body.String()

	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return keys[0].PrivateKey.Public(), nil
		},
	)

	if err != nil {
		t.Fatal(err)
	}

	if !token.Valid {
		t.Fatal("expected token to be valid")
	}

	if token.Header["kid"] != "current-key" {
		t.Fatalf("expected kid current-key, got %v", token.Header["kid"])
	}
}

func TestAuthHandlerExpired(t *testing.T) {
	err := initializeKeys()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth?expired", nil)
	rec := httptest.NewRecorder()

	authHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	tokenString := rec.Body.String()

	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return keys[1].PrivateKey.Public(), nil
		},
	)

	if err == nil {
		t.Fatal("expected expired token to fail validation")
	}

	if token.Header["kid"] != "expired-key" {
		t.Fatalf("expected kid expired-key, got %v", token.Header["kid"])
	}
}

func TestAuthHandlerWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rec := httptest.NewRecorder()

	authHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rec.Code)
	}
}

func TestAuthNoSuitableKey(t *testing.T) {
	oldKeys := keys

	expiredKey, err := generateKey("expired-test", time.Now().Add(-time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}

	keys = []*Key{expiredKey}

	defer func() {
		keys = oldKeys
	}()

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()

	authHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}
}
