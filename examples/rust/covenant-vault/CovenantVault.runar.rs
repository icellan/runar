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
/// 3. **Covenant rule** -- the contract constructs the expected P2PKH output
///    on-chain (recipient address + `min_amount` satoshis) and verifies its
///    hash against the transaction's `hashOutputs` field. This constrains
///    both the destination and the amount at the consensus level.
///
/// Script layout (simplified):
/// ```text
/// Unlocking: <opPushTxSig> <sig> <txPreimage>
/// Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
///            <buildP2PKH(recipient)> <num2bin(minAmount,8)> OP_CAT
///            OP_HASH256 <extractOutputHash(preimage)> OP_EQUAL OP_VERIFY
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
    /// Constructs the expected P2PKH output on-chain and verifies it against
    /// the transaction's hashOutputs from the sighash preimage.
    ///
    /// - `sig`         -- ECDSA signature from the owner (~72 bytes DER).
    /// - `tx_preimage` -- Sighash preimage for `check_preimage` verification.
    #[public]
    pub fn spend(&self, sig: &Sig, tx_preimage: &SigHashPreimage) {
        assert!(check_sig(sig, &self.owner));
        assert!(check_preimage(tx_preimage));

        // Construct expected P2PKH output and verify against hashOutputs
        let script_prefix = cat("1976a914", &self.recipient);
        let p2pkh_script = cat(&script_prefix, "88ac");
        let amount_bytes = num2bin(&self.min_amount, 8);
        let expected_output = cat(&amount_bytes, &p2pkh_script);
        assert!(hash256(&expected_output) == extract_output_hash(tx_preimage));
    }
}
