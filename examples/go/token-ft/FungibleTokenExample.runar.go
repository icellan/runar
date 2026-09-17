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
//   - Merge    -- Merge: 2 UTXOs -> 1 UTXO. Companion-parent merge (W8).
//
// Companion-parent merge (W8 / SoloMerge): authenticates the companion via
// otherParentTx. Input count is not identity. Pin:
// packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
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

// Merge consolidates two token UTXOs into one. Companion-parent merge (W8).
func (c *FungibleToken) Merge(sig runar.Sig, otherBalance runar.Bigint, allPrevouts runar.ByteString, otherParentTx runar.ByteString, outputSatoshis runar.Bigint) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
	runar.Assert(outputSatoshis >= 1)
	runar.Assert(otherBalance >= 0)
	runar.Assert(runar.Len(c.TokenId) > 0)

	pad00 := runar.Num2Bin(0, 1)
	runar.Assert(runar.Hash256(allPrevouts) == runar.ExtractHashPrevouts(c.TxPreimage))
	runar.Assert(runar.Len(allPrevouts) >= 72)

	myOutpoint := runar.ExtractOutpoint(c.TxPreimage)
	firstOutpoint := runar.Substr(allPrevouts, 0, 36)
	secondOutpoint := runar.Substr(allPrevouts, 36, 36)
	companionOutpoint := firstOutpoint
	if myOutpoint == firstOutpoint {
		companionOutpoint = secondOutpoint
	} else {
		runar.Assert(myOutpoint == secondOutpoint)
	}
	companionTxid := runar.Substr(companionOutpoint, 0, 32)
	companionVout := runar.Bin2Num(runar.Cat(runar.Substr(companionOutpoint, 32, 4), pad00))
	runar.Assert(companionVout == 0)
	runar.Assert(runar.Hash256(otherParentTx) == companionTxid)

	inCount := runar.Bin2Num(runar.Cat(runar.Substr(otherParentTx, 4, 1), pad00))
	runar.Assert(inCount >= 1)
	runar.Assert(inCount <= 3)
	off := runar.Bigint(5)
	if 0 < inCount {
		sl := runar.Bin2Num(runar.Cat(runar.Substr(otherParentTx, off+36, 1), pad00))
		runar.Assert(sl < 253)
		off = off + 36 + 1 + sl + 4
	}
	if 1 < inCount {
		sl := runar.Bin2Num(runar.Cat(runar.Substr(otherParentTx, off+36, 1), pad00))
		runar.Assert(sl < 253)
		off = off + 36 + 1 + sl + 4
	}
	if 2 < inCount {
		sl := runar.Bin2Num(runar.Cat(runar.Substr(otherParentTx, off+36, 1), pad00))
		runar.Assert(sl < 253)
		off = off + 36 + 1 + sl + 4
	}
	outCount := runar.Bin2Num(runar.Cat(runar.Substr(otherParentTx, off, 1), pad00))
	runar.Assert(outCount >= 1)
	marker := runar.Bin2Num(runar.Cat(runar.Substr(otherParentTx, off+9, 1), pad00))
	runar.Assert(marker == 253)
	scriptLen := runar.Bin2Num(runar.Cat(runar.Substr(otherParentTx, off+10, 2), pad00))
	scriptStart := off + 12
	runar.Assert(runar.Len(otherParentTx) >= scriptStart+scriptLen)
	companionScript := runar.Substr(otherParentTx, scriptStart, scriptLen)
	runar.Assert(scriptLen > 49)

	sc := runar.ExtractScriptCode(c.TxPreimage)
	scMarker := runar.Bin2Num(runar.Cat(runar.Substr(sc, 0, 1), pad00))
	runar.Assert(scMarker == 253)
	myBody := runar.Substr(sc, 3, runar.Len(sc)-3)
	companionBody := runar.Substr(companionScript, 2, scriptLen-2)
	runar.Assert(runar.Len(myBody) == runar.Len(companionBody))
	runar.Assert(runar.Len(myBody) > 49)
	runar.Assert(runar.Substr(myBody, 0, runar.Len(myBody)-49) == runar.Substr(companionBody, 0, runar.Len(companionBody)-49))

	otherPrimary := runar.Bin2Num(runar.Cat(runar.Substr(companionScript, scriptLen-16, 8), pad00))
	otherMerge := runar.Bin2Num(runar.Cat(runar.Substr(companionScript, scriptLen-8, 8), pad00))
	runar.Assert(otherPrimary+otherMerge == otherBalance)

	myBalance := c.Balance + c.MergeBalance
	if myOutpoint == firstOutpoint {
		c.AddOutput(outputSatoshis, c.Owner, myBalance, otherBalance)
	} else {
		c.AddOutput(outputSatoshis, c.Owner, otherBalance, myBalance)
	}
}
