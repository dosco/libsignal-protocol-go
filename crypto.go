package signal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	KeySize   = 32
	NonceSize = 24
)

// GenerateNonce creates a new random nonce.
func GenerateNonce() (*[NonceSize]byte, error) {
	nonce := new([NonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

func EncryptAEAD(key, message, ad []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, NonceSize)
	if err != nil {
		return nil, err
	}

	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	buf := gcm.Seal(nil, nonce[:], message, ad)
	return append(nonce[:], buf...), nil
}

func DecryptAEAD(key, message, ad []byte) ([]byte, error) {
	if len(message) <= NonceSize {
		return nil, fmt.Errorf("len(message) <= NonceSize")
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(c, NonceSize)
	if err != nil {
		return nil, err
	}

	out, err := gcm.Open(nil, message[:NonceSize], message[NonceSize:], ad)
	if err != nil {
		return nil, err
	}
	return out, nil
}
