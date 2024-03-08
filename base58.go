package main

import (
	"crypto/rand"
	"fmt"
)

var base58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func randomBase58(length int) []byte {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Sprintf("Failed to read bytes from random: '%s'", err))
	}

	for i := range len(b) {
		idx := int(b[i]) % length
		b[i] = base58Alphabet[idx]
	}
	return b
}
