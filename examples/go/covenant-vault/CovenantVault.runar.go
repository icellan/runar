package contract

import runar "github.com/icellan/runar/packages/runar-go"

// CovenantVault is a stateless Bitcoin covenant contract.
//
// A covenant is a self-enforcing spending constraint: the locking script
// dictates not just who can spend the funds, but how they may be spent.
// This contract demonstrates the pattern by combining three verification
// layers in its single public method:
//
//  1. Owner authorization  -- the owner's ECDSA signature must be valid
//     (proves who is spending).
//  2. Preimage verification -- CheckPreimage (OP_PUSH_TX) proves the
//     contract is inspecting the real spending transaction, enabling
//     on-chain introspection of its fields.
//  3. Covenant rule -- the contract constructs the expected P2PKH output
//     on-chain (recipient address + MinAmount satoshis) and verifies its
//     hash against the transaction's hashOutputs field. This constrains
//     both the destination and the amount at the consensus level.
//
// Script layout (simplified):
//
//	Unlocking: <opPushTxSig> <sig> <txPreimage>
//	Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
//	           <buildP2PKH(recipient)> <num2bin(minAmount,8)> OP_CAT
//	           OP_HASH256 <extractOutputHash(preimage)> OP_EQUAL OP_VERIFY
//
// Use cases for this pattern include withdrawal limits, time-locked vaults,
// rate-limited spending, and enforced change addresses.
//
// Contract model: Stateless (SmartContract). All constructor parameters
// are readonly and baked into the locking script at deploy time.
type CovenantVault struct {
	runar.SmartContract
	// Owner is the compressed ECDSA public key (33 bytes) of the vault owner.
	// Only the corresponding private key can produce a valid signature.
	Owner runar.PubKey `runar:"readonly"`
	// Recipient is the address hash (20 bytes, hash160 of pubkey) of the
	// intended recipient.
	Recipient runar.Addr `runar:"readonly"`
	// MinAmount is the minimum output amount in satoshis enforced by the
	// covenant rule.
	MinAmount runar.Bigint `runar:"readonly"`
}

// Spend unlocks funds held by this covenant. Constructs the expected P2PKH
// output on-chain and verifies it against the transaction's hashOutputs.
//
// Parameters:
//   - sig:        ECDSA signature from the owner (~72 bytes DER).
//   - txPreimage: Sighash preimage (variable length) used by CheckPreimage.
func (c *CovenantVault) Spend(sig runar.Sig, txPreimage runar.SigHashPreimage) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(runar.CheckPreimage(txPreimage))

	// Construct expected P2PKH output and verify against hashOutputs
	p2pkhScript := runar.Cat(runar.Cat("1976a914", c.Recipient), "88ac")
	expectedOutput := runar.Cat(runar.Num2Bin(c.MinAmount, 8), p2pkhScript)
	runar.Assert(runar.Hash256(expectedOutput) == runar.ExtractOutputHash(txPreimage))
}
