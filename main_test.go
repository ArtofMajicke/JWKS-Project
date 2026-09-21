package main

import (
	"testing"
)

func TestSetupServer(t *testing.T) {
	err := setupServer()

	if err != nil {
		t.Fatal(err)
	}
}
