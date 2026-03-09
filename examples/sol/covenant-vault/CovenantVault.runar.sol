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
///   3. Covenant rule -- the contract constructs the expected P2PKH output
///      on-chain (recipient address + minAmount satoshis) and verifies its
///      hash against the transaction's hashOutputs field. This constrains
///      both the destination and the amount at the consensus level.
///
/// Script layout (simplified):
///   Unlocking: <opPushTxSig> <sig> <txPreimage>
///   Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
///              <buildP2PKH(recipient)> <num2bin(minAmount,8)> OP_CAT
///              OP_HASH256 <extractOutputHash(preimage)> OP_EQUAL OP_VERIFY
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
    /// @dev Constructs the expected P2PKH output on-chain and verifies it against
    /// the transaction's hashOutputs from the sighash preimage.
    /// @param sig        ECDSA signature from the owner (~72 bytes DER).
    /// @param txPreimage Sighash preimage (variable length) for checkPreimage.
    function spend(Sig sig, SigHashPreimage txPreimage) public {
        require(checkSig(sig, this.owner));
        require(checkPreimage(txPreimage));

        // Construct expected P2PKH output and verify against hashOutputs
        ByteString p2pkhScript = cat(cat(0x1976a914, this.recipient), 0x88ac);
        ByteString expectedOutput = cat(num2bin(this.minAmount, 8), p2pkhScript);
        require(hash256(expectedOutput) == extractOutputHash(txPreimage));
    }
}
