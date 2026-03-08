package contract

import runar "github.com/icellan/runar/packages/runar-go"

// P2PKH — Pay-to-Public-Key-Hash.
//
// The most fundamental Bitcoin spending pattern. Funds are locked to the
// HASH160 (SHA-256 → RIPEMD-160) of a public key. To spend, the recipient
// must provide their full public key (which must hash to the stored hash)
// and a valid ECDSA signature over the transaction.
//
// # How It Works: Two-Step Verification
//
//  1. Hash check — hash160(pubKey) == pubKeyHash proves the provided
//     public key matches the one committed to when the output was created.
//  2. Signature check — checkSig(sig, pubKey) proves the spender
//     holds the private key corresponding to that public key.
//
// This is the same pattern as standard Bitcoin P2PKH transactions, but
// expressed in the Rúnar smart contract language.
//
// # Script Layout
//
//	Unlocking: <sig> <pubKey>
//	Locking:   OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
//
// # Parameter Sizes
//
//   - pubKeyHash: 20 bytes (HASH160 of compressed public key)
//   - sig: ~72 bytes (DER-encoded ECDSA signature + sighash flag)
//   - pubKey: 33 bytes (compressed secp256k1 public key)
type P2PKH struct {
	runar.SmartContract
	PubKeyHash runar.Addr `runar:"readonly"`
}

// Unlock verifies the pubKey hashes to the committed hash, then checks the signature.
func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
	// Step 1: Verify pubKey matches the committed hash
	runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
	// Step 2: Verify ECDSA signature proves ownership of the private key
	runar.Assert(runar.CheckSig(sig, pubKey))
}
