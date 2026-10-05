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
// sig is the DER-encoded signature (raw bytes), optionally followed by one
// sighash type byte (the OP_CHECKSIG convention), which is dropped.
// pubkey is the compressed public key (raw bytes).
// msgHash is the 32-byte message digest to verify against.
func ecdsaVerify(sig, pubkey, msgHash []byte) bool {
	if len(sig) >= 2 && len(sig) == int(sig[1])+3 {
		sig = sig[:len(sig)-1]
	}
	if !isStrictDERSignature(sig) {
		return false
	}
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

// isStrictDERSignature reports whether der (bare DER, no sighash byte) is the
// one canonical encoding of its (r, s) — the BIP66 rule a node applies to
// every OP_CHECKSIG signature (F-242). The SEQUENCE length must cover exactly
// r and s, both INTEGERs must be non-empty, non-negative (top bit clear unless
// behind a 0x00 pad) and minimally encoded, and nothing may follow s.
// go-sdk's ec.ParseDERSignature ignores bytes after the SEQUENCE and
// ec.FromDER (encoding/asn1) does too, so every verifier checks this first.
func isStrictDERSignature(der []byte) bool {
	n := len(der)
	if n < 8 || n > 72 {
		return false
	}
	if der[0] != 0x30 || int(der[1]) != n-2 {
		return false
	}
	rLen := int(der[3])
	if der[2] != 0x02 || rLen == 0 || 5+rLen >= n {
		return false
	}
	sLen := int(der[5+rLen])
	if der[4+rLen] != 0x02 || sLen == 0 || rLen+sLen+6 != n {
		return false
	}
	return isCanonicalDERInteger(der[4:4+rLen]) && isCanonicalDERInteger(der[6+rLen:])
}

// isCanonicalDERInteger: not negative, and no superfluous leading 0x00.
func isCanonicalDERInteger(b []byte) bool {
	if b[0]&0x80 != 0 {
		return false
	}
	return !(len(b) > 1 && b[0] == 0x00 && b[1]&0x80 == 0)
}
