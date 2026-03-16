package runar

// ---------------------------------------------------------------------------
// Test key constants — must match TypeScript test keys exactly
// ---------------------------------------------------------------------------

// TestKeyPair holds a pre-computed ECDSA key pair for testing.
type TestKeyPair struct {
	// PrivKey is the hex-encoded 32-byte private key.
	PrivKey string
	// PubKey is the raw-bytes compressed public key (33 bytes).
	PubKey PubKey
	// PubKeyHash is the raw-bytes HASH160 of the compressed public key (20 bytes).
	PubKeyHash Addr
}

// Alice is a pre-computed test key pair.
// privKey: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
// pubKey:  03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd
// hash160: 9a1c78a507689f6f54b847ad1cef1e614ee23f1e
var Alice = TestKeyPair{
	PrivKey:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	PubKey:     PubKey(string(hexDecode("03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"))),
	PubKeyHash: Addr(string(hexDecode("9a1c78a507689f6f54b847ad1cef1e614ee23f1e"))),
}

// Bob is a pre-computed test key pair.
// privKey: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
// pubKey:  03d6bfe100d1600c0d8f769501676fc74c3809500bd131c8a549f88cf616c21f35
// hash160: 89b460e4e984ef496ff0b135712f3d9b9fc80482
var Bob = TestKeyPair{
	PrivKey:    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	PubKey:     PubKey(string(hexDecode("03d6bfe100d1600c0d8f769501676fc74c3809500bd131c8a549f88cf616c21f35"))),
	PubKeyHash: Addr(string(hexDecode("89b460e4e984ef496ff0b135712f3d9b9fc80482"))),
}

// Charlie is a third test key pair used by contracts that need 3 parties (e.g. Escrow).
// The private key is derived deterministically. PubKey and PubKeyHash are computed at init time.
var Charlie TestKeyPair

func init() {
	charliePriv := "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
	pk := PubKeyFromPrivKey(charliePriv)
	Charlie = TestKeyPair{
		PrivKey:    charliePriv,
		PubKey:     pk,
		PubKeyHash: Hash160(pk),
	}
}
