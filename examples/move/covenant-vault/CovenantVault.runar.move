// CovenantVault -- a stateless Bitcoin covenant contract.
//
// A covenant is a self-enforcing spending constraint: the locking script
// dictates not just *who* can spend the funds, but *how* they may be spent.
// This contract demonstrates the pattern by combining three verification
// layers in its single public method:
//
//   1. Owner authorization  -- the owner's ECDSA signature must be valid
//      (proves who is spending).
//   2. Preimage verification -- check_preimage (OP_PUSH_TX) proves the
//      contract is inspecting the real spending transaction, enabling
//      on-chain introspection of its fields.
//   3. Covenant rule -- the output amount must be >= min_amount, which
//      constrains the transaction structure itself.
//
// Script layout (simplified):
//   Unlocking: <sig> <amount> <txPreimage>
//   Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
//              <amount >= minAmount> OP_VERIFY
//
// Use cases for this pattern include withdrawal limits, time-locked vaults,
// rate-limited spending, and enforced change addresses.
//
// Contract model: Stateless (SmartContract). All fields are readonly and
// baked into the locking script at deploy time.
module CovenantVault {
    use runar::types::{PubKey, Sig, Addr, SigHashPreimage};
    use runar::crypto::{check_sig, check_preimage};

    // Vault state: all fields are readonly constructor parameters.
    //   owner      -- compressed ECDSA public key (33 bytes).
    //   recipient  -- address hash (20-byte hash160 of the recipient's pubkey).
    //   min_amount -- minimum output satoshis enforced by the covenant.
    struct CovenantVault {
        owner: PubKey,
        recipient: Addr,
        min_amount: bigint,
    }

    // Spend funds held by this covenant.
    //
    // Parameters:
    //   sig          -- ECDSA signature from the owner (~72 bytes DER).
    //   amount       -- declared output amount; must be >= min_amount.
    //   tx_preimage  -- sighash preimage (variable length) for check_preimage.
    public fun spend(contract: &CovenantVault, sig: Sig, amount: bigint, tx_preimage: SigHashPreimage) {
        // Layer 1: Owner authorization -- verify the ECDSA signature against
        // the owner's public key.
        assert!(check_sig(sig, contract.owner), 0);

        // Layer 2: Preimage verification -- OP_PUSH_TX proves the contract is
        // inspecting the actual spending transaction, not a forgery.
        assert!(check_preimage(tx_preimage), 0);

        // Layer 3: Covenant rule -- enforce a minimum output amount.
        assert!(amount >= contract.min_amount, 0);
    }
}
