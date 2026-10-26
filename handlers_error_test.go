package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Creates different kinds of invalid or unexpected stored keys.
func makeStoredKeyForTest(t *testing.T, kind string) []byte {
	t.Helper()

	switch kind {
	case "invalid-pem":
		return []byte("this is not a PEM key")

	case "invalid-pkcs8":
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("invalid PKCS8 data"),
		})

	case "non-rsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		data, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}

		return pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: data,
		})
	}

	t.Fatalf("Unknown key type: %s", kind)
	return nil
}

func TestHandlersRejectInvalidStoredKeys(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		keyType string
	}{
		{"JWKS invalid PEM", jwksHandler, http.MethodGet, "invalid-pem"},
		{"JWKS invalid PKCS8", jwksHandler, http.MethodGet, "invalid-pkcs8"},
		{"JWKS non-RSA key", jwksHandler, http.MethodGet, "non-rsa"},
		{"Auth invalid PEM", authHandler, http.MethodPost, "invalid-pem"},
		{"Auth invalid PKCS8", authHandler, http.MethodPost, "invalid-pkcs8"},
		{"Auth non-RSA key", authHandler, http.MethodPost, "non-rsa"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupTestDB(t)

			keyData := makeStoredKeyForTest(t, tt.keyType)
			exp := time.Now().Add(time.Hour).Unix()

			_, err := db.Exec(
				"INSERT INTO keys (key, exp) VALUES (?, ?)",
				keyData, exp,
			)
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest(tt.method, "/", nil)
			rec := httptest.NewRecorder()

			tt.handler(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf(
					"Expected status %d, got %d; body: %s",
					http.StatusInternalServerError,
					rec.Code,
					rec.Body.String(),
				)
			}
		})
	}
}

func TestHandlersDatabaseQueryError(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
	}{
		{"JWKS query error", jwksHandler, http.MethodGet},
		{"Auth query error", authHandler, http.MethodPost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupTestDB(t)

			// Removing the table makes the handler's query fail.
			_, err := db.Exec("DROP TABLE keys")
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest(tt.method, "/", nil)
			rec := httptest.NewRecorder()

			tt.handler(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf(
					"Expected status %d, got %d; body: %s",
					http.StatusInternalServerError,
					rec.Code,
					rec.Body.String(),
				)
			}
		})
	}
}
