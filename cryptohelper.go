package cryptohelper

import (
	"crypto/rand"
	"encoding/base64"
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
