package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
)

const authName = "pangeaAuthCookie"

func signCookie(secret []byte, cookie *http.Cookie) {
	sig := sign(secret, cookie.Name, cookie.Value)
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(sig))
}

func decodeCookie(secret []byte, cookie *http.Cookie) error {
	decoded, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return errors.New("Invalid Signature")
	}

	chunks := bytes.SplitN(decoded, []byte("."), 2)
	if len(chunks) < 2 {
		return errors.New("Invalid Signature")
	}
	value := chunks[0]

	if string(decoded) != sign(secret, cookie.Name, string(value)) {
		return errors.New("Invalid Signature")
	}
	cookie.Value = string(value)
	return nil
}

func sign(secret []byte, name, value string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(name))
	mac.Write([]byte(value))
	signature := mac.Sum(nil)
	return fmt.Sprintf("%s.%s", value, string(signature))
}

type AuthCookie struct {
	ActiveToken  string `json:"a"`
	RefreshToken string `json:"r"`
}
