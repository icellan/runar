package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func setupKeys() (ecdsaPubKey runar.PubKey, ecdsaPubKeyHash runar.Addr, kp runar.WOTSKeyPair, wotsPubKeyHash runar.ByteString) {
	ecdsaPubKey = runar.Alice.PubKey
	ecdsaPubKeyHash = runar.Alice.PubKeyHash

	seed := [32]byte{}
	for i := range seed {
		seed[i] = 0x42
	}
	pubSeed := [32]byte{}
	for i := range pubSeed {
		pubSeed[i] = 0x13
	}
	kp = runar.WotsKeygen(seed[:], pubSeed[:])
	wotsPubKeyHash = runar.Hash160(runar.ByteString(kp.PK))
	return
}

func TestPostQuantumWallet_Spend(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, kp, wotsPubKeyHash := setupKeys()

	c := &PostQuantumWallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		WotsPubKeyHash:  wotsPubKeyHash,
	}

	// Real ECDSA signature
	ecdsaSig := runar.SignTestMessage(runar.Alice.PrivKey)

	// WOTS-sign the ECDSA signature bytes
	wotsSig := runar.WotsSign([]byte(ecdsaSig), kp.SK, kp.PubSeed)

	c.Spend(runar.ByteString(wotsSig), runar.ByteString(kp.PK), ecdsaSig, ecdsaPubKey)
}

func TestPostQuantumWallet_Spend_TamperedWOTS(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, kp, wotsPubKeyHash := setupKeys()

	c := &PostQuantumWallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		WotsPubKeyHash:  wotsPubKeyHash,
	}

	ecdsaSig := runar.SignTestMessage(runar.Alice.PrivKey)
	wotsSig := runar.WotsSign([]byte(ecdsaSig), kp.SK, kp.PubSeed)
	wotsSig[100] ^= 0xff // tamper

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with tampered WOTS signature")
		}
	}()
	c.Spend(runar.ByteString(wotsSig), runar.ByteString(kp.PK), ecdsaSig, ecdsaPubKey)
}

func TestPostQuantumWallet_Spend_WrongECDSASig(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, kp, wotsPubKeyHash := setupKeys()

	c := &PostQuantumWallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		WotsPubKeyHash:  wotsPubKeyHash,
	}

	// Sign one ECDSA sig with WOTS, but provide a different ECDSA sig
	ecdsaSig1 := runar.SignTestMessage(runar.Alice.PrivKey)
	wotsSig := runar.WotsSign([]byte(ecdsaSig1), kp.SK, kp.PubSeed)

	// Create a different message and sign it
	ecdsaSig2 := runar.Sig([]byte{0x30, 0xFF})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail when WOTS signed wrong ECDSA sig")
		}
	}()
	c.Spend(runar.ByteString(wotsSig), runar.ByteString(kp.PK), ecdsaSig2, ecdsaPubKey)
}

func TestPostQuantumWallet_Spend_WrongECDSAPubKeyHash(t *testing.T) {
	_, ecdsaPubKeyHash, kp, wotsPubKeyHash := setupKeys()

	c := &PostQuantumWallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		WotsPubKeyHash:  wotsPubKeyHash,
	}

	// Different ECDSA pubkey whose hash160 won't match
	wrongECDSAPubKey := runar.Bob.PubKey

	ecdsaSig := runar.SignTestMessage(runar.Bob.PrivKey)
	wotsSig := runar.WotsSign([]byte(ecdsaSig), kp.SK, kp.PubSeed)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with wrong ECDSA public key hash")
		}
	}()
	c.Spend(runar.ByteString(wotsSig), runar.ByteString(kp.PK), ecdsaSig, wrongECDSAPubKey)
}

func TestPostQuantumWallet_Spend_WrongWOTSPubKeyHash(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, _, wotsPubKeyHash := setupKeys()

	c := &PostQuantumWallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		WotsPubKeyHash:  wotsPubKeyHash,
	}

	// Different WOTS keypair whose hash160 won't match
	wrongSeed := [32]byte{}
	wrongSeed[0] = 0x99
	wrongPubSeed := [32]byte{}
	wrongPubSeed[0] = 0x77
	wrongKP := runar.WotsKeygen(wrongSeed[:], wrongPubSeed[:])

	ecdsaSig := runar.SignTestMessage(runar.Alice.PrivKey)
	wotsSig := runar.WotsSign([]byte(ecdsaSig), wrongKP.SK, wrongKP.PubSeed)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with wrong WOTS public key hash")
		}
	}()
	c.Spend(runar.ByteString(wotsSig), runar.ByteString(wrongKP.PK), ecdsaSig, ecdsaPubKey)
}

func TestPostQuantumWallet_Compile(t *testing.T) {
	if err := runar.CompileCheck("PostQuantumWallet.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
