package main

import (
	"net/http"
	"testing"
)

func TestSignature(t *testing.T) {

	secret := []byte("foobar")
	cookie := &http.Cookie{
		Name:  "my-cookie",
		Value: "my-value",
	}

	signCookie(secret, cookie)

	if err := decodeCookie(secret, cookie); err != nil {
		t.Errorf("Failed to sign the cookie: %s", err)
		return
	}
}
