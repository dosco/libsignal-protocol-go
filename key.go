package signal

import (
	"crypto/rand"
	"io"
	"math/big"

	"golang.org/x/crypto/curve25519"
)

type PrivKey struct {
	Key [32]byte
}

type PubKey struct {
	Key [32]byte
}

type KeyPair struct {
	Priv *PrivKey
	Pub  *PubKey
}

type PreKey struct {
	KeyID int64
	*KeyPair
}

type SignedPreKey struct {
	KeyID     int64
	Signature *[64]byte
	*KeyPair
}

func GenerateKeyPair() *KeyPair {
	var priv PrivKey
	if _, err := io.ReadFull(rand.Reader, priv.Key[:]); err != nil {
		panic(err)
	}

	priv.Key[0] &= 248
	priv.Key[31] &= 63
	priv.Key[31] |= 64

	var pub PubKey
	curve25519.ScalarBaseMult(&pub.Key, &priv.Key)

	return &KeyPair{Priv: &priv, Pub: &pub}
}

func GenerateRegistrationId() uint64 {
	nBig, err := rand.Int(rand.Reader, big.NewInt(9223372036854775807))
	if err != nil {
		panic(err)
	}
	return nBig.Uint64()
}

func GenerateIdentityKeyPair() *KeyPair {
	return GenerateKeyPair()
}

func GenerateEphemeralKeyPair() *KeyPair {
	return GenerateKeyPair()
}

func GeneratePreKey(keyID int64) *PreKey {
	return &PreKey{keyID, GenerateKeyPair()}
}

func GenerateSignedPreKey(identityKeyPair *KeyPair, keyID int64) *SignedPreKey {
	kp := GenerateKeyPair()

	var random [64]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		panic(err)
	}

	sig := Sign(&identityKeyPair.Priv.Key, kp.Pub.Key[:], random)
	return &SignedPreKey{
		KeyID:     keyID,
		KeyPair:   kp,
		Signature: sig,
	}
}
