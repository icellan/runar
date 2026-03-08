// Three-party escrow contract for marketplace payment protection.
//
// Holds funds in a UTXO until the buyer, seller, or arbiter authorizes
// release. The buyer deposits funds by sending to this contract's locking
// script. Four spending paths allow either party to move funds depending on
// the transaction outcome:
//
//   - release_by_seller  — seller confirms delivery, releases funds to themselves.
//   - release_by_arbiter — arbiter resolves a dispute in the seller's favor.
//   - refund_to_buyer    — buyer cancels before delivery (self-authorized).
//   - refund_by_arbiter  — arbiter resolves a dispute in the buyer's favor.
//
// This is a stateless contract (SmartContract). The three public keys are
// readonly constructor parameters baked into the locking script at deploy time.
//
// Script layout:
//   Unlocking: <methodIndex> <sig>
//   Locking:   OP_IF <release paths> OP_ELSE <refund paths> OP_ENDIF
//
// Each public function becomes an OP_IF branch selected by the method index in
// the unlocking script.
//
// Design note: Each path requires only one signature. A production escrow might
// use 2-of-3 multisig for stronger guarantees, but this contract demonstrates
// the multi-method spending pattern clearly.
module Escrow {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig};

    resource struct Escrow {
        // Buyer's compressed public key (33 bytes).
        buyer: PubKey,
        // Seller's compressed public key (33 bytes).
        seller: PubKey,
        // Arbiter's compressed public key (33 bytes).
        arbiter: PubKey,
    }

    // Seller confirms delivery and releases the escrowed funds.
    // Requires the seller's signature (~72 bytes).
    public fun release_by_seller(contract: &Escrow, sig: Sig) {
        assert!(check_sig(sig, contract.seller), 0);
    }

    // Arbiter resolves a dispute in the seller's favor, releasing funds.
    // Requires the arbiter's signature (~72 bytes).
    public fun release_by_arbiter(contract: &Escrow, sig: Sig) {
        assert!(check_sig(sig, contract.arbiter), 0);
    }

    // Buyer cancels the transaction before delivery and reclaims funds.
    // Requires the buyer's own signature (~72 bytes).
    public fun refund_to_buyer(contract: &Escrow, sig: Sig) {
        assert!(check_sig(sig, contract.buyer), 0);
    }

    // Arbiter resolves a dispute in the buyer's favor, refunding funds.
    // Requires the arbiter's signature (~72 bytes).
    public fun refund_by_arbiter(contract: &Escrow, sig: Sig) {
        assert!(check_sig(sig, contract.arbiter), 0);
    }
}
