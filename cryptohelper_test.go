package cryptohelper

import (
	"encoding/base64"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cryptohelper", func() {
	Describe("Generating random keys", func() {
		It("Doesn't generate the same key twice", func() {
			key1, err := RandomKey()
			Expect(err).To(BeNil())

			key2, err := RandomKey()
			Expect(err).To(BeNil())

			decode1, err := base64.StdEncoding.DecodeString(key1)
			Expect(err).To(BeNil())

			decode2, err := base64.StdEncoding.DecodeString(key2)
			Expect(err).To(BeNil())

			Expect(len([]byte(decode1))).To(Equal(32))
			Expect(len([]byte(decode2))).To(Equal(32))

			Expect(decode1).ToNot(Equal(decode2))
		})
	})

	Describe("Encrypting/decrypting text", func() {
		It("Returns an error if Encrypt is given an invalid key", func() {
			_, err := SecretboxEncrypt("", "")
			Expect(err).To(MatchError("invalid key: must be 32 bytes " +
				"b64-encoded"))
		})

		It("Returns an error if Decrypt is given an invalid key", func() {
			_, err := SecretboxDecrypt("", "")
			Expect(err).To(MatchError("invalid key: must be 32 bytes " +
				"b64-encoded"))
		})

		It("Encrypts a message and decrypts it back", func() {
			message := "hello"

			key, err := RandomKey()
			Expect(err).To(BeNil())

			ciphertext, err := SecretboxEncrypt(message, key)
			Expect(err).To(BeNil())

			plaintext, err := SecretboxDecrypt(ciphertext, key)
			Expect(err).To(BeNil())
			Expect(plaintext).To(Equal(message))
		})

		It("Fails HMAC when the ciphertext is tampered with", func() {
			message := "hello"

			key, err := RandomKey()
			Expect(err).To(BeNil())

			ciphertext, err := SecretboxEncrypt(message, key)
			Expect(err).To(BeNil())

			// remove the last byte from the cipher text
			cipherBytes, err := base64.StdEncoding.DecodeString(ciphertext)
			Expect(err).To(BeNil())
			cipherBytes = cipherBytes[:len(cipherBytes)-1]
			tampered := base64.StdEncoding.EncodeToString(cipherBytes)

			_, err = SecretboxDecrypt(tampered, key)
			Expect(err).To(MatchError("ciphertext failed to authenticate HMAC"))
		})

		It("Ensures that the ciphertext contains a randomized nonce", func() {
			message := "hello"

			key, err := RandomKey()
			Expect(err).To(BeNil())

			cipher1, err := SecretboxEncrypt(message, key)
			Expect(err).To(BeNil())

			cipher2, err := SecretboxEncrypt(message, key)
			Expect(err).To(BeNil())

			Expect(cipher1).ToNot(Equal(cipher2))
		})
	})
})

func TestCryptohelper(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cryptohelper Suite")
}
