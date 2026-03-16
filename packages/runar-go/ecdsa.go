package runar

import (
	"crypto/sha256"
	"encoding/hex"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// ---------------------------------------------------------------------------
// Test message constants — must match TypeScript's TEST_MESSAGE exactly
// ---------------------------------------------------------------------------

// TestMessage is the canonical test message: UTF-8 bytes of "runar-test-message-v1" (21 bytes).
var TestMessage = []byte("runar-test-message-v1")

// TestMessageDigest is SHA256(TestMessage). ECDSA signing/verification uses this as the hash.
var TestMessageDigest = sha256.Sum256(TestMessage)

// ---------------------------------------------------------------------------
// ECDSA helpers — real signing and verification using go-sdk
// ---------------------------------------------------------------------------

// SignTestMessage signs TEST_MESSAGE using the given private key (hex string).
// Returns a DER-encoded ECDSA signature as raw bytes (Sig = ByteString = string).
func SignTestMessage(privKeyHex string) Sig {
	privKey, err := ec.PrivateKeyFromHex(privKeyHex)
	if err != nil {
		panic("runar: SignTestMessage: invalid private key hex: " + err.Error())
	}
	sig, err := privKey.Sign(TestMessageDigest[:])
	if err != nil {
		panic("runar: SignTestMessage: signing failed: " + err.Error())
	}
	return Sig(sig.Serialize())
}

// PubKeyFromPrivKey derives the compressed public key from a hex-encoded private key.
// Returns raw bytes as PubKey (ByteString = string).
func PubKeyFromPrivKey(privKeyHex string) PubKey {
	privKey, err := ec.PrivateKeyFromHex(privKeyHex)
	if err != nil {
		panic("runar: PubKeyFromPrivKey: invalid private key hex: " + err.Error())
	}
	return PubKey(privKey.PubKey().Compressed())
}

// ecdsaVerify performs real ECDSA verification.
// sig is the DER-encoded signature (raw bytes).
// pubkey is the compressed public key (raw bytes).
// msgHash is the 32-byte message digest to verify against.
func ecdsaVerify(sig, pubkey, msgHash []byte) bool {
	parsedSig, err := ec.ParseDERSignature(sig)
	if err != nil {
		return false
	}
	parsedPK, err := ec.ParsePubKey(pubkey)
	if err != nil {
		return false
	}
	return parsedSig.Verify(msgHash, parsedPK)
}

// hexDecode decodes a hex string to raw bytes. Panics on invalid hex.
func hexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("runar: hexDecode: " + err.Error())
	}
	return b
}
