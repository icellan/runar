package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func setupP256Keys() (ecdsaPubKey runar.PubKey, ecdsaPubKeyHash runar.Addr, kp runar.P256KeyPair, p256PubKeyHash runar.ByteString) {
	ecdsaPubKey = runar.Alice.PubKey
	ecdsaPubKeyHash = runar.Alice.PubKeyHash

	kp = runar.P256Keygen()
	p256PubKeyHash = runar.Hash160(runar.ByteString(kp.PKCompressed))
	return
}

func TestP256Wallet_Spend(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, kp, p256PubKeyHash := setupP256Keys()

	c := &P256Wallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		P256PubKeyHash:  p256PubKeyHash,
	}

	// Real secp256k1 signature (sig bytes ARE the P-256 message)
	ecdsaSig := runar.SignTestMessage(runar.Alice.PrivKey)

	// P-256-sign the secp256k1 signature bytes
	p256Sig := runar.P256Sign([]byte(ecdsaSig), kp.SK)

	c.Spend(runar.ByteString(p256Sig), runar.ByteString(kp.PKCompressed), ecdsaSig, ecdsaPubKey)
}

func TestP256Wallet_Spend_TamperedP256Sig(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, kp, p256PubKeyHash := setupP256Keys()

	c := &P256Wallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		P256PubKeyHash:  p256PubKeyHash,
	}

	ecdsaSig := runar.SignTestMessage(runar.Alice.PrivKey)
	p256Sig := runar.P256Sign([]byte(ecdsaSig), kp.SK)
	p256Sig[0] ^= 0xff // tamper

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with tampered P-256 signature")
		}
	}()
	c.Spend(runar.ByteString(p256Sig), runar.ByteString(kp.PKCompressed), ecdsaSig, ecdsaPubKey)
}

func TestP256Wallet_Spend_WrongECDSASig(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, kp, p256PubKeyHash := setupP256Keys()

	c := &P256Wallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		P256PubKeyHash:  p256PubKeyHash,
	}

	// P-256-sign one secp256k1 sig, but provide a different one
	ecdsaSig1 := runar.SignTestMessage(runar.Alice.PrivKey)
	p256Sig := runar.P256Sign([]byte(ecdsaSig1), kp.SK)

	ecdsaSig2 := runar.Sig([]byte{0x30, 0xFF})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail when P-256 signed wrong secp256k1 sig")
		}
	}()
	c.Spend(runar.ByteString(p256Sig), runar.ByteString(kp.PKCompressed), ecdsaSig2, ecdsaPubKey)
}

func TestP256Wallet_Spend_WrongECDSAPubKeyHash(t *testing.T) {
	_, ecdsaPubKeyHash, kp, p256PubKeyHash := setupP256Keys()

	c := &P256Wallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		P256PubKeyHash:  p256PubKeyHash,
	}

	// Different secp256k1 pubkey whose hash160 won't match
	wrongECDSAPubKey := runar.Bob.PubKey

	ecdsaSig := runar.SignTestMessage(runar.Bob.PrivKey)
	p256Sig := runar.P256Sign([]byte(ecdsaSig), kp.SK)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with wrong secp256k1 public key hash")
		}
	}()
	c.Spend(runar.ByteString(p256Sig), runar.ByteString(kp.PKCompressed), ecdsaSig, wrongECDSAPubKey)
}

func TestP256Wallet_Spend_WrongP256PubKeyHash(t *testing.T) {
	ecdsaPubKey, ecdsaPubKeyHash, _, p256PubKeyHash := setupP256Keys()

	c := &P256Wallet{
		EcdsaPubKeyHash: ecdsaPubKeyHash,
		P256PubKeyHash:  p256PubKeyHash,
	}

	// Different P-256 keypair whose hash160 won't match
	wrongKP := runar.P256Keygen()

	ecdsaSig := runar.SignTestMessage(runar.Alice.PrivKey)
	p256Sig := runar.P256Sign([]byte(ecdsaSig), wrongKP.SK)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected spend to fail with wrong P-256 public key hash")
		}
	}()
	c.Spend(runar.ByteString(p256Sig), runar.ByteString(wrongKP.PKCompressed), ecdsaSig, ecdsaPubKey)
}

func TestP256Wallet_Compile(t *testing.T) {
	if err := runar.CompileCheck("P256Wallet.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
