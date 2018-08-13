package signal

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var diversifier = [32]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

type derivedKeys struct {
	rootKey  [32]byte
	chainKey [32]byte
	index    uint32
}

type messageKeys struct {
	CipherKey []byte
	MacKey    []byte
	Iv        []byte
	Index     uint32
}

func (dk *derivedKeys) getMessageKeys() (*messageKeys, error) {
	m := hmac.New(sha256.New, dk.chainKey[:])
	m.Write([]byte{1})
	b := m.Sum(nil)

	okm := HKDF(b, nil, []byte("WhisperMessageKeys"), 80)
	return &messageKeys{
		CipherKey: okm[:32],
		MacKey:    okm[32:64],
		Iv:        okm[64:],
		Index:     dk.index,
	}, nil
}

func (dk *derivedKeys) nextChainKey() [32]byte {
	m := hmac.New(sha256.New, dk.chainKey[:])
	m.Write([]byte{2})
	b := m.Sum(nil)

	dk.index += 1
	copy(dk.chainKey[:], b)
	return dk.chainKey
}

func DH(priv *PrivKey, pub *PubKey) *[32]byte {
	var sharedKey [32]byte
	curve25519.ScalarMult(&sharedKey, &priv.Key, &pub.Key)
	return &sharedKey
}

func KDF(dh ...[]byte) *derivedKeys {
	fkm := make([]byte, 0, 32*5)
	fkm = append(fkm, diversifier[:]...)

	for i := range dh {
		fkm = append(fkm, dh[i]...)
	}
	b := HKDF(fkm, nil, []byte("WhisperText"), 64)
	dk := &derivedKeys{index: 0}
	copy(dk.rootKey[:], b[:32])
	copy(dk.chainKey[:], b[32:])

	return dk
}

func HKDF(km, salt, info []byte, size int) []byte {
	hkdf := hkdf.New(sha256.New, km, salt, info)

	secrets := make([]byte, size)
	n, err := io.ReadFull(hkdf, secrets)
	if err != nil {
		panic(err)
	}
	if n != size {
		panic(fmt.Errorf("error n != size"))
	}
	return secrets
}

type BobPreKeyBundle struct {
	Recipient      *Address
	RegistrationId uint64
	DeviceID       uint32

	IdentityKeyPub *PubKey

	SignedPreKeyID        uint32
	SignedPreKeyPub       *PubKey
	SignedPreKeySignature *[64]byte

	OneTimePreKeyID  int32
	OneTimePreKeyPub *PubKey
}

type SenderSession struct {
	store Store

	sk *derivedKeys
	ad []byte

	identityKeyPub  *PubKey
	ephemeralKeyPub *PubKey

	signedPreKeyID  uint32
	oneTimePreKeyID int32
}

func NewSenderSession(store Store, b *BobPreKeyBundle) (*SenderSession, error) {
	s := &SenderSession{store: store}

	//if !b.identityStore.IsTrustedIdentity(b.recipientID, theirIdentityKey) {
	//	return 0, NotTrustedError{sb.recipientID}
	//}

	spkB := b.SignedPreKeyPub
	if !Verify(b.IdentityKeyPub.Key, spkB.Key[:], b.SignedPreKeySignature) {
		return nil, fmt.Errorf("verify signed pre-key failed")
	}

	identityKeyPair, err := s.store.GetIdentityKeyPair()
	if err != nil {
		return nil, err
	}
	ikA := identityKeyPair.Priv
	ikB := b.IdentityKeyPub

	ephemeralKeyPair := GenerateEphemeralKeyPair()
	ekA := ephemeralKeyPair.Priv
	opkB := b.OneTimePreKeyPub

	s.ad = append(identityKeyPair.Pub.Key[:], b.IdentityKeyPub.Key[:]...)

	// SKAD
	dh1 := DH(ikA, spkB)
	dh2 := DH(ekA, ikB)
	dh3 := DH(ekA, spkB)
	dhList := [][]byte{dh1[:], dh2[:], dh3[:]}

	if opkB != nil {
		dh4 := DH(ekA, opkB)
		dhList = append(dhList, dh4[:])
	}

	// TODO: Delete dh values
	s.sk = KDF(dhList...)

	s.identityKeyPub = identityKeyPair.Pub
	s.ephemeralKeyPub = ephemeralKeyPair.Pub

	s.signedPreKeyID = b.SignedPreKeyID
	s.oneTimePreKeyID = b.OneTimePreKeyID

	return s, nil
}

type AliceMessage struct {
	identityKeyPub  *PubKey
	ephemeralKeyPub *PubKey

	signedPreKeyID  uint32
	oneTimePreKeyID int32

	ciphertext []byte
}

func (s *SenderSession) sendFirstMessage(message []byte) (*AliceMessage, error) {
	var err error

	am := AliceMessage{
		identityKeyPub:  s.identityKeyPub,
		ephemeralKeyPub: s.ephemeralKeyPub,
		signedPreKeyID:  s.signedPreKeyID,
		oneTimePreKeyID: s.oneTimePreKeyID,
	}
	if s.sk.index == 0 {
		am.ciphertext, err = EncryptAEAD(s.sk.chainKey[:], message, s.ad)
		if err != nil {
			return nil, err
		}
		return &am, nil
	}
	return nil, fmt.Errorf("chain index != 0 (%d)", s.sk.index)
}

type message struct {
}

func (s *SenderSession) sendNextMessage(message []byte) (*message, error) {
	/*
		mk, err := s.sk.getMessageKeys()
		if err != nil {
			return nil, err
		}

		ciphertext, err := Encrypt(mk.CipherKey, mk.Iv, message)
		if err != nil {
			return nil, err
		}

		fmt.Printf("%q", ciphertext)
	*/
	return nil, nil
}

type ReceiverSession struct {
	store Store

	sk *derivedKeys
	ad []byte

	ciphertext []byte
}

func NewReceiverSession(store Store, a *AliceMessage) (*ReceiverSession, error) {
	s := ReceiverSession{
		store:      store,
		ciphertext: a.ciphertext,
	}

	signedPreKey, err := s.store.GetSignedPreKey(a.signedPreKeyID)
	if err != nil {
		return nil, err
	}
	spkB := signedPreKey.Priv

	identityKeyPair, err := s.store.GetIdentityKeyPair()
	if err != nil {
		return nil, err
	}
	ikA := a.identityKeyPub
	ikB := identityKeyPair.Priv

	ekA := a.ephemeralKeyPub

	var opkB *PrivKey
	if a.oneTimePreKeyID != -1 {
		preKey, err := s.store.GetPreKey(uint32(a.oneTimePreKeyID))
		if err != nil {
			return nil, err
		}
		opkB = preKey.Priv
	}

	s.ad = append(a.identityKeyPub.Key[:], identityKeyPair.Pub.Key[:]...)

	// SKAD
	dh1 := DH(spkB, ikA)
	dh2 := DH(ikB, ekA)
	dh3 := DH(spkB, ekA)
	dhList := [][]byte{dh1[:], dh2[:], dh3[:]}

	if opkB != nil {
		dh4 := DH(opkB, ekA)
		dhList = append(dhList, dh4[:])
	}

	// TODO: Delete dh values
	s.sk = KDF(dhList...)
	return &s, nil
}

func (s *ReceiverSession) processFirstMessage() (string, error) {
	plaintext, err := DecryptAEAD(s.sk.chainKey[:], s.ciphertext, s.ad)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
