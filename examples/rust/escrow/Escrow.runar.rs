use runar::prelude::*;

/// Three-party escrow contract for marketplace payment protection.
///
/// Holds funds in a UTXO until the buyer, seller, or arbiter authorizes
/// release. The buyer deposits funds by sending to this contract's locking
/// script. Four spending paths allow either party to move funds depending on
/// the transaction outcome:
///
/// - [`release_by_seller`]  — seller confirms delivery, releases funds to themselves.
/// - [`release_by_arbiter`] — arbiter resolves a dispute in the seller's favor.
/// - [`refund_to_buyer`]    — buyer cancels before delivery (self-authorized).
/// - [`refund_by_arbiter`]  — arbiter resolves a dispute in the buyer's favor.
///
/// This is a stateless contract (`SmartContract`). The three public keys are
/// readonly constructor parameters baked into the locking script at deploy time.
///
/// # Script layout
///
/// ```text
/// Unlocking: <methodIndex> <sig>
/// Locking:   OP_IF <release paths> OP_ELSE <refund paths> OP_ENDIF
/// ```
///
/// Each public method becomes an `OP_IF` branch selected by the method index in
/// the unlocking script.
///
/// # Design note
///
/// Each path requires only one signature. A production escrow might use 2-of-3
/// multisig for stronger guarantees, but this contract demonstrates the
/// multi-method spending pattern clearly.
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
    /// Seller confirms delivery and releases the escrowed funds.
    /// Requires the seller's signature (~72 bytes).
    #[public]
    pub fn release_by_seller(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.seller));
    }

    /// Arbiter resolves a dispute in the seller's favor, releasing funds.
    /// Requires the arbiter's signature (~72 bytes).
    #[public]
    pub fn release_by_arbiter(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.arbiter));
    }

    /// Buyer cancels the transaction before delivery and reclaims funds.
    /// Requires the buyer's own signature (~72 bytes).
    #[public]
    pub fn refund_to_buyer(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.buyer));
    }

    /// Arbiter resolves a dispute in the buyer's favor, refunding funds.
    /// Requires the arbiter's signature (~72 bytes).
    #[public]
    pub fn refund_by_arbiter(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.arbiter));
    }
}
