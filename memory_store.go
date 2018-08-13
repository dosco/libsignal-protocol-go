package signal

import "fmt"

type MemoryStore struct {
	localRegistrationID uint64
	identityKeyPair     *KeyPair
	identityKeys        map[uint32]*[32]byte
	preKeys             map[uint32]*PreKey
	signedPreKeys       map[uint32]*SignedPreKey
}

var (
	NotFound error = fmt.Errorf("not found")
)

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		identityKeys:  make(map[uint32]*[32]byte),
		preKeys:       make(map[uint32]*PreKey),
		signedPreKeys: make(map[uint32]*SignedPreKey),
	}
}

func (s *MemoryStore) GetLocalRegistrationID() (uint64, error) {
	return s.localRegistrationID, nil
}

func (s *MemoryStore) PutLocalRegistrationID(id uint64) error {
	s.localRegistrationID = id
	return nil
}

func (s *MemoryStore) GetIdentityKeyPair() (*KeyPair, error) {
	return s.identityKeyPair, nil
}

func (s *MemoryStore) PutIdentityKeyPair(keyPair *KeyPair) error {
	s.identityKeyPair = keyPair
	return nil
}

func (s *MemoryStore) GetIdentityKey(keyID uint32) (*[32]byte, error) {
	v, ok := s.identityKeys[keyID]
	if ok {
		return v, nil
	}
	return nil, NotFound
}

func (s *MemoryStore) PutIdentityKey(keyID uint32, identityKey *[32]byte) error {
	s.identityKeys[keyID] = identityKey
	return nil
}

func (s *MemoryStore) GetPreKey(keyID uint32) (*PreKey, error) {
	v, ok := s.preKeys[keyID]
	if ok {
		return v, nil
	}
	return nil, NotFound
}

func (s *MemoryStore) PutPreKey(keyID uint32, preKey *PreKey) error {
	s.preKeys[keyID] = preKey
	return nil
}

func (s *MemoryStore) GetSignedPreKey(keyID uint32) (*SignedPreKey, error) {
	v, ok := s.signedPreKeys[keyID]
	if ok {
		return v, nil
	}
	return nil, NotFound
}

func (s *MemoryStore) PutSignedPreKey(keyID uint32, signedPreKey *SignedPreKey) error {
	s.signedPreKeys[keyID] = signedPreKey
	return nil
}
