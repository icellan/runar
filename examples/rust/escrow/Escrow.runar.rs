use runar::prelude::*;

/// Three-party escrow contract for marketplace payment protection.
///
/// Holds funds in a UTXO until two parties jointly authorize a spend.
/// The buyer deposits funds by sending to this contract's locking script.
/// Two spending paths allow funds to move depending on the transaction outcome:
///
/// - [`release`] — seller + arbiter both sign to release funds to the seller
///   (e.g., goods delivered successfully).
/// - [`refund`]  — buyer + arbiter both sign to refund funds to the buyer
///   (e.g., dispute resolved in buyer's favor).
///
/// The arbiter serves as the trust anchor — no single party can act alone.
/// Both paths require two signatures (dual-sig), ensuring the arbiter must
/// co-sign every spend. This prevents unilateral action by either party.
///
/// Script layout:
/// ```text
/// Unlocking: <methodIndex> <sig1> <sig2>
/// Locking:   OP_IF <seller checkSig> <arbiter checkSig>
///            OP_ELSE <buyer checkSig> <arbiter checkSig> OP_ENDIF
/// ```
#[runar::contract]
pub struct Escrow {
    /// Buyer's compressed public key (33 bytes).
    #[readonly]
    pub buyer: PubKey,
    /// Seller's compressed public key (33 bytes).
    #[readonly]
    pub seller: PubKey,
    /// Arbiter's compressed public key (33 bytes).
    #[readonly]
    pub arbiter: PubKey,
}

#[runar::methods(Escrow)]
impl Escrow {
    /// Release escrowed funds to the seller.
    /// Requires both the seller's and arbiter's signatures.
    #[public]
    pub fn release(&self, seller_sig: &Sig, arbiter_sig: &Sig) {
        assert!(check_sig(seller_sig, &self.seller));
        assert!(check_sig(arbiter_sig, &self.arbiter));
    }

    /// Refund escrowed funds to the buyer.
    /// Requires both the buyer's and arbiter's signatures.
    #[public]
    pub fn refund(&self, buyer_sig: &Sig, arbiter_sig: &Sig) {
        assert!(check_sig(buyer_sig, &self.buyer));
        assert!(check_sig(arbiter_sig, &self.arbiter));
    }
}
