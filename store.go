package signal

type Store interface {
	GetIdentityKeyPair() (*KeyPair, error)

	PutIdentityKeyPair(keyPair *KeyPair) error

	GetLocalRegistrationID() (uint64, error)

	PutLocalRegistrationID(id uint64) error

	GetIdentityKey(keyID uint32) (*[32]byte, error)

	PutIdentityKey(keyID uint32, identityKey *[32]byte) error

	GetPreKey(keyID uint32) (*PreKey, error)

	PutPreKey(keyID uint32, preKey *PreKey) error

	GetSignedPreKey(keyID uint32) (*SignedPreKey, error)

	PutSignedPreKey(keyID uint32, signedPreKey *SignedPreKey) error
}
