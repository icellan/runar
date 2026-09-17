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
//   - Merge    -- Merge: 2 UTXOs -> 1 UTXO (UNSOUND: does not authenticate a second token input; W8 / SoloMerge)
//
// UNSOUND merge (W8 / SoloMerge): Merge never asserts that a second token
// covenant is an input of the spending transaction. hash256(allPrevouts) ===
// extractHashPrevouts(preimage) only proves allPrevouts is the real prevout
// list. A one-input spend takes the "I am input 0" arm and writes the
// spender-chosen otherBalance into the successor. A P2PKH fee input filling
// len(allPrevouts) == 72 does not close the hole. Pin:
// packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
// For a construction that binds a specific companion input, see
// examples/ts/companion-verifier/.
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

// Merge consolidates two token UTXOs into one.
// (2 UTXOs -> 1 UTXO)
//
// UNSOUND (W8 / SoloMerge): this method does not authenticate a second
// token input. The position-dependent slot construction below is the
// intended two-input argument; its premise (a second input running this
// covenant) is never checked. A one-input spend writes otherBalance into
// the successor. Pin:
// packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
//
// What the script actually does, if two token inputs happen to be present:
// each input writes its own locking-script balance to a slot based on
// whether its outpoint is first in allPrevouts, and hashOutputs then
// forces those two inputs to agree. That is not a proof that a second
// token input exists.
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
