package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Escrow is a three-party escrow contract for marketplace payment protection.
//
// Holds funds in a UTXO until two parties jointly authorize a spend. The buyer
// deposits funds by sending to this contract's locking script. Two spending
// paths allow funds to move depending on the transaction outcome:
//
//   - Release — seller + arbiter both sign to release funds to the seller
//     (e.g., goods delivered successfully).
//   - Refund  — buyer + arbiter both sign to refund funds to the buyer
//     (e.g., dispute resolved in buyer's favor).
//
// The arbiter serves as the trust anchor — no single party can act alone.
// Both paths require two signatures (dual-sig), ensuring the arbiter must
// co-sign every spend. This prevents unilateral action by either party.
//
// Script layout:
//
//	Unlocking: <methodIndex> <sig1> <sig2>
//	Locking:   OP_IF <seller checkSig> <arbiter checkSig>
//	           OP_ELSE <buyer checkSig> <arbiter checkSig> OP_ENDIF
//
// This is a stateless contract (SmartContract). The three public keys are
// readonly constructor parameters baked into the locking script at deploy time.
type Escrow struct {
	runar.SmartContract
	// Buyer is the buyer's compressed public key (33 bytes).
	Buyer runar.PubKey `runar:"readonly"`
	// Seller is the seller's compressed public key (33 bytes).
	Seller runar.PubKey `runar:"readonly"`
	// Arbiter is the arbiter's compressed public key (33 bytes).
	Arbiter runar.PubKey `runar:"readonly"`
}

// Release releases escrowed funds to the seller.
// Requires both the seller's and arbiter's signatures.
func (c *Escrow) Release(sellerSig runar.Sig, arbiterSig runar.Sig) {
	runar.Assert(runar.CheckSig(sellerSig, c.Seller))
	runar.Assert(runar.CheckSig(arbiterSig, c.Arbiter))
}

// Refund refunds escrowed funds to the buyer.
// Requires both the buyer's and arbiter's signatures.
func (c *Escrow) Refund(buyerSig runar.Sig, arbiterSig runar.Sig) {
	runar.Assert(runar.CheckSig(buyerSig, c.Buyer))
	runar.Assert(runar.CheckSig(arbiterSig, c.Arbiter))
}
