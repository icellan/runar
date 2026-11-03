pragma runar ^0.1.0;

/// @title Notary
/// @notice F-352 second witness for the mutable-state shape
/// {ByteString, PubKey, bigint}, with the PubKey declared first.
contract Notary is StatefulSmartContract {
    PubKey signer;
    ByteString note;
    bigint seq;

    constructor(PubKey _signer, ByteString _note, bigint _seq) {
        signer = _signer;
        note = _note;
        seq = _seq;
    }

    function notarize(Sig sig, ByteString nextNote) public {
        require(checkSig(sig, this.signer));
        this.note = nextNote;
        this.seq = this.seq + 1;
    }
}
