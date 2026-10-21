pragma runar ^0.1.0;

/// @title Ledger
/// @notice F-352 second witness for the mutable-state shape
/// {PubKey, bigint, bigint}.
contract Ledger is StatefulSmartContract {
    PubKey holder;
    bigint balance;
    bigint nonce;

    constructor(PubKey _holder, bigint _balance, bigint _nonce) {
        holder = _holder;
        balance = _balance;
        nonce = _nonce;
    }

    function spend(Sig sig, bigint amount) public {
        require(checkSig(sig, this.holder));
        require(amount > 0);
        require(amount <= this.balance);
        this.balance = this.balance - amount;
        this.nonce = this.nonce + 1;
    }
}
