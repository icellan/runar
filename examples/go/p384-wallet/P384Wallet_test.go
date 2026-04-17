package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func setupP384Keys() (ecdsaPubKey runar.PubKey, ecdsaPubKeyHash runar.Addr, kp runar.P384KeyPair, p384PubKeyHash runar.ByteString) {
	ecdsaPubKey = runar.Alice.PubKey
	ecdsaPubKeyHash = runar.Alice.PubKeyHash

	kp = runar.P384Keygen()
	p384PubKeyHash = runar.Hash160(runar.ByteString(kp.PKCompressed))
	return
}

func TestP384Wallet_Spend(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, kp, p384PubKeyHash := setupP384Keys()

	c := &P384Wallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		P384PubKeyHash:  p384PubKeyHash,
	}

	// Real secp256k1 signature (sig bytes ARE the P-384 message)
	ecdsaSig := runar.SignTestMessage(runar.Alice.PrivKey)

	// P-384-sign the secp256k1 signature bytes
	p384Sig := runar.P384Sign([]byte(ecdsaSig), kp.SK)

	c.Spend(runar.ByteString(p384Sig), runar.ByteString(kp.PKCompressed), ecdsaSig, ecdsaPubKey)
}

func TestP384Wallet_Spend_TamperedP384Sig(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, kp, p384PubKeyHash := setupP384Keys()

	c := &P384Wallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		P384PubKeyHash:  p384PubKeyHash,
	}

	ecdsaSig := runar.SignTestMessage(runar.Alice.PrivKey)
	p384Sig := runar.P384Sign([]byte(ecdsaSig), kp.SK)
	p384Sig[0] ^= 0xff // tamper

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with tampered P-384 signature")
		}
	}()
	c.Spend(runar.ByteString(p384Sig), runar.ByteString(kp.PKCompressed), ecdsaSig, ecdsaPubKey)
}

func TestP384Wallet_Spend_WrongECDSASig(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, kp, p384PubKeyHash := setupP384Keys()

	c := &P384Wallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		P384PubKeyHash:  p384PubKeyHash,
	}

	// P-384-sign one secp256k1 sig, but provide a different one
	ecdsaSig1 := runar.SignTestMessage(runar.Alice.PrivKey)
	p384Sig := runar.P384Sign([]byte(ecdsaSig1), kp.SK)

	ecdsaSig2 := runar.Sig([]byte{0x30, 0xFF})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail when P-384 signed wrong secp256k1 sig")
		}
	}()
	c.Spend(runar.ByteString(p384Sig), runar.ByteString(kp.PKCompressed), ecdsaSig2, ecdsaPubKey)
}

func TestP384Wallet_Spend_WrongECDSAPubKeyHash(t *testing.T) {
	_, ecdsaPubKeyHash, kp, p384PubKeyHash := setupP384Keys()

	c := &P384Wallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		P384PubKeyHash:  p384PubKeyHash,
	}

	// Different secp256k1 pubkey whose hash160 won't match
	wrongECDSAPubKey := runar.Bob.PubKey

	ecdsaSig := runar.SignTestMessage(runar.Bob.PrivKey)
	p384Sig := runar.P384Sign([]byte(ecdsaSig), kp.SK)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with wrong secp256k1 public key hash")
		}
	}()
	c.Spend(runar.ByteString(p384Sig), runar.ByteString(kp.PKCompressed), ecdsaSig, wrongECDSAPubKey)
}

func TestP384Wallet_Spend_WrongP384PubKeyHash(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, _, p384PubKeyHash := setupP384Keys()

	c := &P384Wallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		P384PubKeyHash:  p384PubKeyHash,
	}

	// Different P-384 keypair whose hash160 won't match
	wrongKP := runar.P384Keygen()

	ecdsaSig := runar.SignTestMessage(runar.Alice.PrivKey)
	p384Sig := runar.P384Sign([]byte(ecdsaSig), wrongKP.SK)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with wrong P-384 public key hash")
		}
	}()
	c.Spend(runar.ByteString(p384Sig), runar.ByteString(wrongKP.PKCompressed), ecdsaSig, ecdsaPubKey)
}

func TestP384Wallet_Compile(t *testing.T) {
	if err := runar.CompileCheck("P384Wallet.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
