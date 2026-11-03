pragma runar ^0.1.0;

/// @title AnnotatedVault
/// @notice N-044 conformance fixture: a mutable variable-length ByteString
/// state field (`memo`) BEFORE a mutable PubKey (`owner`). Anyone may replace
/// the memo; only the owner may withdraw.
contract AnnotatedVault is StatefulSmartContract {
    ByteString memo;
    PubKey owner;
    bigint balance;

    constructor(ByteString _memo, PubKey _owner, bigint _balance) {
        memo = _memo;
        owner = _owner;
        balance = _balance;
    }

    /// @notice Replace the memo. Anyone can call.
    function annotate(ByteString nextMemo) public {
        this.memo = nextMemo;
    }

    /// @notice Only the owner may spend.
    function withdraw(Sig sig) public {
        require(checkSig(sig, this.owner));
    }
}
