package contract

import runar "github.com/icellan/runar/packages/runar-go"

// Escrow is a three-party escrow contract for marketplace payment protection.
//
// It holds funds in a UTXO until the buyer, seller, or arbiter authorizes
// release. The buyer deposits funds by sending to this contract's locking
// script. Four spending paths allow either party to move funds depending on
// the transaction outcome:
//
//   - ReleaseBySeller  — seller confirms delivery, releases funds to themselves.
//   - ReleaseByArbiter — arbiter resolves a dispute in the seller's favor.
//   - RefundToBuyer    — buyer cancels before delivery (self-authorized).
//   - RefundByArbiter  — arbiter resolves a dispute in the buyer's favor.
//
// This is a stateless contract (SmartContract). The three public keys are
// readonly constructor parameters baked into the locking script at deploy time.
//
// Script layout:
//
//	Unlocking: <methodIndex> <sig>
//	Locking:   OP_IF <release paths> OP_ELSE <refund paths> OP_ENDIF
//
// Each public method becomes an OP_IF branch selected by the method index in
// the unlocking script.
//
// Design note: Each path requires only one signature. A production escrow might
// use 2-of-3 multisig for stronger guarantees, but this contract demonstrates
// the multi-method spending pattern clearly.
//
// Fields:
//
//	Buyer   — buyer's compressed public key (33 bytes)
//	Seller  — seller's compressed public key (33 bytes)
//	Arbiter — arbiter's compressed public key (33 bytes)
type Escrow struct {
	runar.SmartContract
	Buyer  runar.PubKey `runar:"readonly"`
	Seller runar.PubKey `runar:"readonly"`
	Arbiter runar.PubKey `runar:"readonly"`
}

// ReleaseBySeller allows the seller to confirm delivery and release the
// escrowed funds. Requires the seller's signature (~72 bytes).
func (c *Escrow) ReleaseBySeller(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Seller))
}

// ReleaseByArbiter allows the arbiter to resolve a dispute in the seller's
// favor, releasing the escrowed funds. Requires the arbiter's signature (~72 bytes).
func (c *Escrow) ReleaseByArbiter(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Arbiter))
}

// RefundToBuyer allows the buyer to cancel the transaction before delivery
// and reclaim the escrowed funds. Requires the buyer's own signature (~72 bytes).
func (c *Escrow) RefundToBuyer(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Buyer))
}

// RefundByArbiter allows the arbiter to resolve a dispute in the buyer's
// favor, refunding the escrowed funds. Requires the arbiter's signature (~72 bytes).
func (c *Escrow) RefundByArbiter(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Arbiter))
}
