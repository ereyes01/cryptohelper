// Package cryptohelper provides very simple-to-use wrappers around NaCl's
// secretbox package. This package only provides convenience functions, but
// does not try to actually do any of the crypto... that is best left to the
// experts!
//
// The Go implementations of NaCl and secretbox are documented here:
// https://godoc.org/golang.org/x/crypto/nacl/secretbox
//
// This package basically does the following:
//  - Implements a 256-bit random key generator using Go's rand library.
//  - Wraps the secretbox Open/Seal routines with functions that read and write
//    base64-encoded data
//  - When encrypting, randomly generates a 24-bit nonce and prepends it to the
//    ciphertext, which altogether is encoded in the b64 buffer.
//  - When decrypting split the enbedded nonce from the ciphertext.
//
// This page claims there's a negligible collision risk when randomly
// generating nonces: http://nacl.cr.yp.to/secretbox.html
package cryptohelper

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
)

// RandomKey generates 32 random bytes suitable for use as a key to NaCl's
// secretbox crypto library. The key is returned b64-encoded.
func RandomKey() (string, error) {
	var key [32]byte

	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(key[:])
	return encoded, nil
}

func decodeKey(key string) ([]byte, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	if len(keyBytes) != 32 {
		return nil, errors.New("invalid key: must be 32 bytes b64-encoded")
	}

	return keyBytes, nil
}

// Encrypt returns a b64-encoded buffer consisting of a random 24-bit nonce
// followed by the ciphertext encrypted with the given key using NaCl's
// secretbox implementation. The given key must be a b64-encoded 32-byte buffer.
func Encrypt(plaintext string, key string) (string, error) {
	var (
		keyArr [32]byte
		nonce  [24]byte
	)

	keyBytes, err := decodeKey(key)
	if err != nil {
		return "", err
	}

	copy(keyArr[:], keyBytes)

	// This page claims there's a negligible collision risk when randomly
	// generating nonces: http://nacl.cr.yp.to/secretbox.html
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}

	// The nonce is embedded with the returned buffer:
	// [--nonce(24by)--][--ciphertext--]
	ciphertext := secretbox.Seal(nonce[:], []byte(plaintext), &nonce, &keyArr)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt accepts a b64-encoded buffer consisting of a random 24-bit nonce
// followed by the ciphertext, and a b64-encoded 32-byte buffer containing the
// encryption key. The function will use NaCl's secretbox implementation to
// decrypt the ciphertext with the embedded nonce. The plaintext is returned in
// the absence of errors.
//
// NaCl includes an HMAC within the ciphertext- if the ciphertext is tampered
// with, the HMAC authentication fails, and this function will return an error
// informing you of that.
func Decrypt(ciphertext string, key string) (string, error) {
	var (
		keyArr [32]byte
		nonce  [24]byte
	)

	keyBytes, err := decodeKey(key)
	if err != nil {
		return "", err
	}

	cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	copy(nonce[:], cipherBytes[:24])
	copy(keyArr[:], keyBytes)

	plaintext, ok := secretbox.Open([]byte{}, cipherBytes[24:], &nonce, &keyArr)
	if !ok {
		return "", errors.New("ciphertext failed to authenticate HMAC")
	}

	return string(plaintext), nil
}
