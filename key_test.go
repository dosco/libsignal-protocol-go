package signal

import "testing"

func TestFlow(t *testing.T) {
	msA := NewMemoryStore()
	msB := NewMemoryStore()

	// Alice
	idA := GenerateRegistrationId()
	msA.PutLocalRegistrationID(idA)

	ikpA := GenerateIdentityKeyPair()
	msA.PutIdentityKeyPair(ikpA)

	pkA := GeneratePreKey(1)
	msA.PutPreKey(1, pkA)

	spkA := GenerateSignedPreKey(ikpA, 1)
	msA.PutSignedPreKey(1, spkA)

	// Bob

	idB := GenerateRegistrationId()
	msB.PutLocalRegistrationID(idB)

	ikpB := GenerateIdentityKeyPair()
	msB.PutIdentityKeyPair(ikpB)

	pkB := GeneratePreKey(1)
	msB.PutPreKey(1, pkB)

	spkB := GenerateSignedPreKey(ikpB, 1)
	msB.PutSignedPreKey(1, spkB)

	bobPreKeys := BobPreKeyBundle{
		Recipient:      NewAddress("+141566112222", 1),
		RegistrationId: idB,
		DeviceID:       1,

		IdentityKeyPub: ikpB.Pub,

		SignedPreKeyID:        1,
		SignedPreKeyPub:       spkB.Pub,
		SignedPreKeySignature: spkB.Signature,

		OneTimePreKeyID:  1,
		OneTimePreKeyPub: pkB.Pub,
	}

	ss, err := NewSenderSession(msA, &bobPreKeys)
	if err != nil {
		t.Fatal(err)
	}

	aliceMsg, err := ss.sendFirstMessage([]byte("Hello World!!!"))
	if err != nil {
		t.Fatal(err)
	}

	rs, err := NewReceiverSession(msB, aliceMsg)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := rs.processFirstMessage()
	if err != nil {
		t.Fatal(err)
	}

	if plaintext != "Hello World!!!" {
		t.Errorf("Message failed to decrypt")
	}

	t.Logf("Decryption successful: %s", plaintext)

}
