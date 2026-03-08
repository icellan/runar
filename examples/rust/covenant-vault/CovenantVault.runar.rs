use runar::prelude::*;

/// A stateless Bitcoin covenant contract.
///
/// A covenant is a self-enforcing spending constraint: the locking script
/// dictates not just *who* can spend the funds, but *how* they may be spent.
/// This contract demonstrates the pattern by combining three verification
/// layers in its single public method:
///
/// 1. **Owner authorization** -- the owner's ECDSA signature must be valid
///    (proves who is spending).
/// 2. **Preimage verification** -- `check_preimage` (OP_PUSH_TX) proves the
///    contract is inspecting the real spending transaction, enabling
///    on-chain introspection of its fields.
/// 3. **Covenant rule** -- the output amount must be >= `min_amount`, which
///    constrains the transaction structure itself.
///
/// Script layout (simplified):
/// ```text
/// Unlocking: <sig> <amount> <txPreimage>
/// Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
///            <amount >= minAmount> OP_VERIFY
/// ```
///
/// Use cases for this pattern include withdrawal limits, time-locked vaults,
/// rate-limited spending, and enforced change addresses.
///
/// Contract model: Stateless (`SmartContract`). All constructor parameters
/// are readonly and baked into the locking script at deploy time.
#[runar::contract]
pub struct CovenantVault {
    /// Owner's compressed ECDSA public key (33 bytes).
    #[readonly]
    pub owner: PubKey,
    /// Recipient address (20-byte hash160 of the recipient's public key).
    #[readonly]
    pub recipient: Addr,
    /// Minimum output amount in satoshis enforced by the covenant.
    #[readonly]
    pub min_amount: Bigint,
}

#[runar::methods(CovenantVault)]
impl CovenantVault {
    /// Spend funds held by this covenant.
    ///
    /// The caller must supply three pieces of evidence:
    /// - `sig`        -- ECDSA signature from the owner (~72 bytes DER).
    /// - `amount`     -- Declared output amount; must be >= `min_amount`.
    /// - `tx_preimage` -- Sighash preimage (variable length) used by
    ///   `check_preimage` to verify the spending transaction.
    #[public]
    pub fn spend(&self, sig: &Sig, amount: Bigint, tx_preimage: &SigHashPreimage) {
        // Layer 1: Owner authorization -- verify the ECDSA signature against
        // the owner's public key.
        assert!(check_sig(sig, &self.owner));
        // Layer 2: Preimage verification -- OP_PUSH_TX proves the contract is
        // inspecting the actual spending transaction, not a forgery.
        assert!(check_preimage(tx_preimage));
        // Layer 3: Covenant rule -- enforce a minimum output amount.
        assert!(amount >= self.min_amount);
    }
}
