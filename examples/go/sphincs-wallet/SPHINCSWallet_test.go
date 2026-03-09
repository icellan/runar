package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// deterministic seed for reproducible tests
var testSeed = func() []byte {
	s := make([]byte, 3*16) // 3*n for SLH-DSA-128s (n=16)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}()

var testKP = runar.SLHKeygen(runar.SLH_SHA2_128s, testSeed)

func setupSPHINCSKeys() (ecdsaPubKey runar.PubKey, ecdsaPubKeyHash runar.Addr, slhdsaPubKeyHash runar.ByteString) {
	ecdsaPubKey = runar.MockPubKey()
	ecdsaPubKeyHash = runar.Hash160(ecdsaPubKey)
	slhdsaPubKeyHash = runar.Hash160(runar.ByteString(testKP.PK))
	return
}

func TestSPHINCSWallet_Spend(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, slhdsaPubKeyHash := setupSPHINCSKeys()

	c := &SPHINCSWallet{
		EcdsaPubKeyHash:  ecdsaPubKeyHash,
		SlhdsaPubKeyHash: slhdsaPubKeyHash,
	}

	// Mock ECDSA signature (CheckSig is mocked to true)
	ecdsaSig := runar.MockSig()

	// SLH-DSA-sign the ECDSA signature bytes
	slhdsaSig := runar.SLHSign(runar.SLH_SHA2_128s, []byte(ecdsaSig), testKP.SK)

	c.Spend(runar.ByteString(slhdsaSig), runar.ByteString(testKP.PK), ecdsaSig, ecdsaPubKey)
}

func TestSPHINCSWallet_Spend_MultipleMessages(t *testing.T) {
	// SLH-DSA is stateless — same keypair can sign many messages
	ecdsaPubKey, ecdsaPubKeyHash, slhdsaPubKeyHash := setupSPHINCSKeys()

	c := &SPHINCSWallet{
		EcdsaPubKeyHash:  ecdsaPubKeyHash,
		SlhdsaPubKeyHash: slhdsaPubKeyHash,
	}

	// First spend
	ecdsaSig1 := runar.Sig(make([]byte, 72))
	ecdsaSig1 = runar.Sig(append([]byte{0x30, 0x01}, make([]byte, 70)...))
	slhdsaSig1 := runar.SLHSign(runar.SLH_SHA2_128s, []byte(ecdsaSig1), testKP.SK)
	c.Spend(runar.ByteString(slhdsaSig1), runar.ByteString(testKP.PK), ecdsaSig1, ecdsaPubKey)

	// Second spend (same SLH-DSA keypair, different ECDSA sig)
	ecdsaSig2 := runar.Sig(append([]byte{0x30, 0x02}, make([]byte, 70)...))
	slhdsaSig2 := runar.SLHSign(runar.SLH_SHA2_128s, []byte(ecdsaSig2), testKP.SK)
	c.Spend(runar.ByteString(slhdsaSig2), runar.ByteString(testKP.PK), ecdsaSig2, ecdsaPubKey)
}

func TestSPHINCSWallet_Spend_TamperedSLHDSA(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, slhdsaPubKeyHash := setupSPHINCSKeys()

	c := &SPHINCSWallet{
		EcdsaPubKeyHash:  ecdsaPubKeyHash,
		SlhdsaPubKeyHash: slhdsaPubKeyHash,
	}

	ecdsaSig := runar.MockSig()
	slhdsaSig := runar.SLHSign(runar.SLH_SHA2_128s, []byte(ecdsaSig), testKP.SK)
	slhdsaSig[0] ^= 0xff // tamper

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with tampered SLH-DSA signature")
		}
	}()
	c.Spend(runar.ByteString(slhdsaSig), runar.ByteString(testKP.PK), ecdsaSig, ecdsaPubKey)
}

func TestSPHINCSWallet_Spend_WrongECDSASig(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, slhdsaPubKeyHash := setupSPHINCSKeys()

	c := &SPHINCSWallet{
		EcdsaPubKeyHash:  ecdsaPubKeyHash,
		SlhdsaPubKeyHash: slhdsaPubKeyHash,
	}

	// Sign one ECDSA sig with SLH-DSA, but provide a different ECDSA sig
	ecdsaSig1 := runar.MockSig()
	slhdsaSig := runar.SLHSign(runar.SLH_SHA2_128s, []byte(ecdsaSig1), testKP.SK)

	ecdsaSig2 := runar.Sig([]byte{0x30, 0xFF})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail when SLH-DSA signed wrong ECDSA sig")
		}
	}()
	c.Spend(runar.ByteString(slhdsaSig), runar.ByteString(testKP.PK), ecdsaSig2, ecdsaPubKey)
}

func TestSPHINCSWallet_Spend_WrongECDSAPubKeyHash(t *testing.T) {
	_, ecdsaPubKeyHash, slhdsaPubKeyHash := setupSPHINCSKeys()

	c := &SPHINCSWallet{
		EcdsaPubKeyHash:  ecdsaPubKeyHash,
		SlhdsaPubKeyHash: slhdsaPubKeyHash,
	}

	// Different ECDSA pubkey whose hash160 won't match
	wrongBytes := make([]byte, 33)
	wrongBytes[0] = 0x03
	for i := 1; i < 33; i++ {
		wrongBytes[i] = 0xff
	}
	wrongECDSAPubKey := runar.PubKey(wrongBytes)

	ecdsaSig := runar.MockSig()
	slhdsaSig := runar.SLHSign(runar.SLH_SHA2_128s, []byte(ecdsaSig), testKP.SK)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with wrong ECDSA public key hash")
		}
	}()
	c.Spend(runar.ByteString(slhdsaSig), runar.ByteString(testKP.PK), ecdsaSig, wrongECDSAPubKey)
}

func TestSPHINCSWallet_Spend_WrongSLHDSAPubKeyHash(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, slhdsaPubKeyHash := setupSPHINCSKeys()

	c := &SPHINCSWallet{
		EcdsaPubKeyHash:  ecdsaPubKeyHash,
		SlhdsaPubKeyHash: slhdsaPubKeyHash,
	}

	// Different SLH-DSA keypair whose hash160 won't match
	wrongSeed := make([]byte, 3*16)
	for i := range wrongSeed {
		wrongSeed[i] = 0xff
	}
	wrongKP := runar.SLHKeygen(runar.SLH_SHA2_128s, wrongSeed)

	ecdsaSig := runar.MockSig()
	slhdsaSig := runar.SLHSign(runar.SLH_SHA2_128s, []byte(ecdsaSig), wrongKP.SK)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with wrong SLH-DSA public key hash")
		}
	}()
	c.Spend(runar.ByteString(slhdsaSig), runar.ByteString(wrongKP.PK), ecdsaSig, ecdsaPubKey)
}

func TestSPHINCSWallet_Compile(t *testing.T) {
	if err := runar.CompileCheck("SPHINCSWallet.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
