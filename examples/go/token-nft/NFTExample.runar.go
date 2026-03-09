package contract

import runar "github.com/icellan/runar/packages/runar-go"

// SimpleNFT is a non-fungible token (NFT) represented as a single UTXO.
//
// Unlike fungible tokens, an NFT is indivisible -- the token IS the UTXO. This contract
// demonstrates ownership transfer and burn (permanent destruction) of a unique digital asset,
// enforced entirely by Bitcoin Script.
//
// UTXO as NFT:
// Each NFT is a single UTXO carrying:
//   - Owner (mutable): current owner's public key, updated on transfer
//   - TokenId (readonly): unique identifier baked into the locking script
//   - Metadata (readonly): content hash or URI, also baked in and immutable
//
// Operations:
//   - Transfer -- Changes ownership. Creates one continuation UTXO via AddOutput with a new owner.
//   - Burn     -- Destroys the token permanently. No AddOutput = no continuation UTXO = token ceases to exist.
//
// Authorization: Both operations require the current owner's ECDSA signature via CheckSig.
type SimpleNFT struct {
	runar.StatefulSmartContract
	Owner    runar.PubKey     // Current owner's public key. Mutable -- updated when the NFT is transferred.
	TokenId  runar.ByteString `runar:"readonly"` // Unique token identifier. Readonly -- baked into the locking script at deploy time.
	Metadata runar.ByteString `runar:"readonly"` // Token metadata (content hash or URI). Readonly -- immutable for the token's lifetime.
}

// Transfer changes ownership of the NFT to a new owner.
//
// Creates one continuation UTXO via AddOutput with the new owner. TokenId and Metadata
// remain unchanged (readonly properties are baked into the locking script).
// AddOutput(satoshis, owner) takes the single mutable property positionally.
//
// Parameters:
//   - sig: current owner's signature (authorization)
//   - newOwner: new owner's public key
//   - outputSatoshis: satoshis to fund the continuation UTXO
func (c *SimpleNFT) Transfer(sig runar.Sig, newOwner runar.PubKey, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(outputSatoshis >= 1)
	c.AddOutput(outputSatoshis, newOwner)
}

// Burn permanently destroys the NFT.
//
// The owner signs to authorize destruction. Because this method does not call AddOutput
// and does not mutate state, the compiler generates no state continuation. The UTXO is
// simply spent with no successor -- the token ceases to exist on-chain.
//
// Parameters:
//   - sig: current owner's signature (authorization)
func (c *SimpleNFT) Burn(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	// No AddOutput and no state mutation = token destroyed
}
