pragma runar ^0.1.0;

/// @title MultiSig2of3
/// @notice A 2-of-3 multi-signature contract. Funds unlock when any two of
/// the three committed public keys produce valid ECDSA signatures.
/// @dev `checkMultiSig([sig1, sig2], [this.pk1, this.pk2, this.pk3])` lowers
/// to two `array_literal` ANF nodes — one per array argument. This contract
/// is the canonical cross-compiler fixture for `array_literal` coverage.
///
/// Script layout:
///   Unlocking: <sig1> <sig2>
///   Locking:   OP_0 <sig1> <sig2> 2 <pk1> <pk2> <pk3> 3 OP_CHECKMULTISIG
///              OP_VERIFY
contract MultiSig2of3 is SmartContract {
    /// @notice First committed public key (33 bytes compressed).
    PubKey immutable pk1;
    /// @notice Second committed public key (33 bytes compressed).
    PubKey immutable pk2;
    /// @notice Third committed public key (33 bytes compressed).
    PubKey immutable pk3;

    constructor(PubKey _pk1, PubKey _pk2, PubKey _pk3) {
        pk1 = _pk1;
        pk2 = _pk2;
        pk3 = _pk3;
    }

    /// @notice Spend requires two valid signatures from any two of the
    /// three committed pubkeys.
    function unlock(Sig sig1, Sig sig2) public {
        require(checkMultiSig([sig1, sig2], [this.pk1, this.pk2, this.pk3]));
    }
}
