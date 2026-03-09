package contract

import runar "github.com/icellan/runar/packages/runar-go"

// FungibleToken is a UTXO-based fungible token using Runar's multi-output (AddOutput) facility.
//
// It demonstrates how to model divisible token balances that can be split, transferred, and
// merged -- similar to colored coins or SLP-style tokens but enforced entirely by Bitcoin Script.
//
// UTXO token model vs account model:
// Unlike Ethereum ERC-20 where balances live in a global mapping, each token "balance" here
// is a separate UTXO. The UTXO carries state: the current owner (PubKey), balance (Bigint),
// and an immutable TokenId (ByteString). Transferring tokens means spending one UTXO and
// creating new ones with updated state.
//
// Operations:
//   - Transfer -- Split: 1 UTXO -> 2 UTXOs (recipient + change back to sender)
//   - Send     -- Simple send: 1 UTXO -> 1 UTXO (full balance to new owner)
//   - Merge    -- Secure merge: 2 UTXOs -> 1 UTXO (consolidate two token UTXOs)
//
// Secure merge design:
// The merge uses position-dependent output construction verified via hashPrevouts.
// Each input reads its own balance from its locking script (verified by OP_PUSH_TX)
// and writes it to a specific slot in the output based on its position in the transaction.
// Since hashOutputs forces both inputs to agree on the exact same output, each input's
// claimed otherBalance must equal the other input's real verified balance.
// This prevents the inflation attack where an attacker lies about otherBalance.
//
// The output stores both individual balances (Balance and MergeBalance) so they can
// be independently verified. Subsequent operations use the sum as the available balance.
//
// Authorization: All operations require the current owner's ECDSA signature via CheckSig.
type FungibleToken struct {
	runar.StatefulSmartContract
	Owner        runar.PubKey     // Current owner's public key. Mutable -- updated on ownership transfer.
	Balance      runar.Bigint     // Primary token balance. Mutable -- adjusted on transfer/split/merge.
	MergeBalance runar.Bigint     // Secondary balance slot used during merge for cross-input verification. Normally 0.
	TokenId      runar.ByteString `runar:"readonly"` // Unique token identifier. Readonly -- baked into the locking script, cannot change.
}

// Transfer sends tokens to a recipient. If the full balance is sent, produces 1 output;
// otherwise produces 2 outputs (recipient + change back to sender).
//
// Uses AddOutput twice to create two continuation UTXOs in the spending transaction.
// AddOutput(satoshis, ...stateValues) takes positional state values matching mutable
// properties in declaration order: Owner, Balance, MergeBalance.
//
// Parameters:
//   - sig: current owner's signature (authorization)
//   - to: recipient's public key
//   - amount: number of tokens to send (must be > 0 and <= current balance)
//   - outputSatoshis: satoshis to fund each output UTXO
func (c *FungibleToken) Transfer(sig runar.Sig, to runar.PubKey, amount runar.Bigint, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(outputSatoshis >= 1)
	totalBalance := c.Balance + c.MergeBalance
	runar.Assert(amount > 0)
	runar.Assert(amount <= totalBalance)

	// First output: recipient receives `amount` tokens
	c.AddOutput(outputSatoshis, to, amount, 0)
	// Second output: sender keeps the remaining balance as change (skip if fully spent)
	if amount < totalBalance {
		c.AddOutput(outputSatoshis, c.Owner, totalBalance-amount, 0)
	}
}

// Send transfers the entire balance to a new owner in a single output.
// (1 UTXO -> 1 UTXO)
//
// Creates a single continuation UTXO with the same balance but a new owner.
//
// Parameters:
//   - sig: current owner's signature (authorization)
//   - to: new owner's public key
//   - outputSatoshis: satoshis to fund the output UTXO
func (c *FungibleToken) Send(sig runar.Sig, to runar.PubKey, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(outputSatoshis >= 1)

	c.AddOutput(outputSatoshis, to, c.Balance+c.MergeBalance, 0)
}

// Merge securely consolidates two token UTXOs into one.
// (2 UTXOs -> 1 UTXO)
//
// Why this is secure (anti-inflation proof):
//
// Each input reads its own balance from its locking script (c.Balance), which is
// verified by OP_PUSH_TX — it cannot be faked. Each input writes its verified balance
// to a specific output slot based on its position in the transaction.
//
// Position is derived from allPrevouts (verified against hashPrevouts in the
// preimage, so it reflects the real transaction) and the input's own outpoint.
//
// The output has two balance slots: Balance (slot 0) and MergeBalance (slot 1).
// Each input places its own verified balance in its slot, and the claimed otherBalance
// in the other slot:
//
//	Input 0 (balance=400): AddOutput(sats, owner, 400, otherBalance_0)
//	Input 1 (balance=600): AddOutput(sats, owner, otherBalance_1, 600)
//
// Both inputs must produce byte-identical outputs (enforced by hashOutputs in BIP-143).
// This forces:
//   - slot 0: 400 == otherBalance_1  ->  input 1 MUST pass 400
//   - slot 1: otherBalance_0 == 600  ->  input 0 MUST pass 600
//
// Any lie causes a hashOutputs mismatch and the transaction is rejected on-chain.
// The inputs can be in any order — each self-discovers its position from the preimage.
//
// Parameters:
//   - sig: current owner's signature (authorization)
//   - otherBalance: claimed balance of the other merging input
//   - allPrevouts: concatenated outpoints of all tx inputs (verified via hashPrevouts)
//   - outputSatoshis: satoshis to fund the merged output UTXO
func (c *FungibleToken) Merge(sig runar.Sig, otherBalance runar.Bigint, allPrevouts runar.ByteString, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(outputSatoshis >= 1)
	runar.Assert(otherBalance >= 0)

	// Verify allPrevouts is authentic (matches the actual transaction inputs)
	runar.Assert(runar.Hash256(allPrevouts) == runar.ExtractHashPrevouts(c.TxPreimage))

	// Determine position: am I the first contract input?
	myOutpoint := runar.ExtractOutpoint(c.TxPreimage)
	firstOutpoint := runar.Substr(allPrevouts, 0, 36)
	myBalance := c.Balance + c.MergeBalance

	if myOutpoint == firstOutpoint {
		// I'm input 0: my verified balance goes to slot 0
		c.AddOutput(outputSatoshis, c.Owner, myBalance, otherBalance)
	} else {
		// I'm input 1: my verified balance goes to slot 1
		c.AddOutput(outputSatoshis, c.Owner, otherBalance, myBalance)
	}
}
