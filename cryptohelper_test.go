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
})

func TestCryptohelper(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cryptohelper Suite")
}
