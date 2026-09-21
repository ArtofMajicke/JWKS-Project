package main

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

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

	_, err := generateKey("test-key", time.Now().Unix())

	if err == nil {
		t.Fatal("expected generateKey to return an error")
	}
}

func TestInitializeKeysFirstError(t *testing.T) {
	oldGenerateKeyFunc := generateKeyFunc

	generateKeyFunc = func(kid string, expiresAt int64) (*Key, error) {
		return nil, errors.New("forced error")
	}

	defer func() {
		generateKeyFunc = oldGenerateKeyFunc
	}()

	err := initializeKeys()

	if err == nil {
		t.Fatal("expected initializeKeys to return an error")
	}
}

func TestInitializeKeysSecondError(t *testing.T) {
	oldGenerateKeyFunc := generateKeyFunc
	callCount := 0

	generateKeyFunc = func(kid string, expiresAt int64) (*Key, error) {
		callCount++

		if callCount == 2 {
			return nil, errors.New("forced error")
		}

		return generateKey(kid, expiresAt)
	}

	defer func() {
		generateKeyFunc = oldGenerateKeyFunc
	}()

	err := initializeKeys()

	if err == nil {
		t.Fatal("expected initializeKeys to return an error")
	}
}
