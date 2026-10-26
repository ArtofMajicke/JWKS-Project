package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

func insertTestKey(t *testing.T, exp int64) (*rsa.PrivateKey, int64) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	result, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		privatePEM,
		exp,
	)
	if err != nil {
		t.Fatal(err)
	}

	kid, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	return privateKey, kid
}

func TestAuthHandler(t *testing.T) {
	setupTestDB(t)

	privateKey, kid := insertTestKey(
		t,
		time.Now().Add(time.Hour).Unix(),
	)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()

	authHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s",
			rec.Code, rec.Body.String())
	}

	tokenString := rec.Body.String()

	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return privateKey.Public(), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if !token.Valid {
		t.Fatal("expected token to be valid")
	}

	expectedKid := strconv.FormatInt(kid, 10)
	if token.Header["kid"] != expectedKid {
		t.Fatalf("expected kid %s, got %v",
			expectedKid, token.Header["kid"])
	}
}

func TestAuthHandlerExpired(t *testing.T) {
	setupTestDB(t)

	privateKey, kid := insertTestKey(
		t,
		time.Now().Add(-time.Hour).Unix(),
	)

	req := httptest.NewRequest(
		http.MethodPost, "/auth?expired", nil,
	)
	rec := httptest.NewRecorder()

	authHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s",
			rec.Code, rec.Body.String())
	}

	token, err := jwt.Parse(
		rec.Body.String(),
		func(token *jwt.Token) (interface{}, error) {
			return privateKey.Public(), nil
		},
		jwt.WithoutClaimsValidation(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !token.Valid {
		t.Fatal("expected signature to be valid")
	}

	expectedKid := strconv.FormatInt(kid, 10)
	if token.Header["kid"] != expectedKid {
		t.Fatalf("expected kid %s, got %v",
			expectedKid, token.Header["kid"])
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
	setupTestDB(t)

	insertTestKey(
		t,
		time.Now().Add(-time.Hour).Unix(),
	)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()

	authHandler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}
}
