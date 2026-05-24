pragma runar ^0.1.0;

/// @title AllReadonlyCleanstack — regression fixture for issue #44.
/// @notice A StatefulSmartContract with ZERO mutable fields (only a readonly
/// `owner`) plus a readonly-field-binding in a terminal method. The
/// `ownerCopy = owner` binding force-embeds the readonly field onto the stack;
/// it is not consumed by the terminal `checkSig` assertion, leaving an excess
/// stack item below the top-of-stack boolean. Before the fix, the leftover
/// survived and the spend was rejected on mainnet with "Script did not clean
/// its stack". The fix runs `cleanupExcessStack()` for every public method,
/// emitting the trailing OP_NIP that balances the stack.
contract AllReadonlyCleanstack is StatefulSmartContract {
    PubKey immutable owner;

    constructor(PubKey _owner) {
        owner = _owner;
    }

    function claim(Sig sig) public {
        PubKey ownerCopy = owner;
        require(checkSig(sig, owner));
    }
}
