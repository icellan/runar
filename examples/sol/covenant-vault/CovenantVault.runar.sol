// SPDX-License-Identifier: MIT
pragma runar ^0.1.0;

/// @title CovenantVault
/// @notice A stateless Bitcoin covenant contract.
///
/// A covenant is a self-enforcing spending constraint: the locking script
/// dictates not just *who* can spend the funds, but *how* they may be spent.
/// This contract demonstrates the pattern by combining three verification
/// layers in its single public method:
///
///   1. Owner authorization  -- the owner's ECDSA signature must be valid
///      (proves who is spending).
///   2. Preimage verification -- checkPreimage (OP_PUSH_TX) proves the
///      contract is inspecting the real spending transaction, enabling
///      on-chain introspection of its fields.
///   3. Covenant rule -- the output amount must be >= minAmount, which
///      constrains the transaction structure itself.
///
/// Script layout (simplified):
///   Unlocking: <sig> <amount> <txPreimage>
///   Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
///              <amount >= minAmount> OP_VERIFY
///
/// Use cases for this pattern include withdrawal limits, time-locked vaults,
/// rate-limited spending, and enforced change addresses.
///
/// Contract model: Stateless (SmartContract). All constructor parameters
/// are immutable and baked into the locking script at deploy time.
contract CovenantVault is SmartContract {
    /// @notice Owner's compressed ECDSA public key (33 bytes).
    PubKey immutable owner;
    /// @notice Recipient address (20-byte hash160 of the recipient's pubkey).
    Addr immutable recipient;
    /// @notice Minimum output amount in satoshis enforced by the covenant.
    bigint immutable minAmount;

    /// @param _owner     Owner's compressed ECDSA public key (33 bytes).
    /// @param _recipient Recipient address hash (20 bytes).
    /// @param _minAmount Minimum output satoshis enforced by the covenant.
    constructor(PubKey _owner, Addr _recipient, bigint _minAmount) {
        owner = _owner;
        recipient = _recipient;
        minAmount = _minAmount;
    }

    /// @notice Spend funds held by this covenant.
    /// @param sig        ECDSA signature from the owner (~72 bytes DER).
    /// @param amount     Declared output amount; must be >= minAmount.
    /// @param txPreimage Sighash preimage (variable length) for checkPreimage.
    function spend(Sig sig, bigint amount, SigHashPreimage txPreimage) public {
        // Layer 1: Owner authorization -- verify the ECDSA signature against
        // the owner's public key.
        require(checkSig(sig, this.owner));

        // Layer 2: Preimage verification -- OP_PUSH_TX proves the contract is
        // inspecting the actual spending transaction, not a forgery.
        require(checkPreimage(txPreimage));

        // Layer 3: Covenant rule -- enforce a minimum output amount. This is
        // the core covenant constraint: it restricts how funds are spent,
        // not just who can spend them.
        require(amount >= this.minAmount);
    }
}
