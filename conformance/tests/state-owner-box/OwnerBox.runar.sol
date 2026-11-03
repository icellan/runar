pragma runar ^0.1.0;

/// @title OwnerBox
/// @notice F-352 second witness for the mutable-state shape {PubKey}.
contract OwnerBox is StatefulSmartContract {
    PubKey owner;

    constructor(PubKey _owner) {
        owner = _owner;
    }

    function rotate(Sig sig, PubKey newOwner) public {
        require(checkSig(sig, this.owner));
        this.owner = newOwner;
    }
}
