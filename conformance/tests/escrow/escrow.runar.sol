pragma runar ^0.1.0;

contract Escrow is SmartContract {
    PubKey immutable buyer;
    PubKey immutable seller;
    PubKey immutable arbiter;

    constructor(PubKey _buyer, PubKey _seller, PubKey _arbiter) {
        buyer = _buyer;
        seller = _seller;
        arbiter = _arbiter;
    }

    function release(Sig sellerSig, Sig arbiterSig) public {
        require(checkSig(sellerSig, this.seller));
        require(checkSig(arbiterSig, this.arbiter));
    }

    function refund(Sig buyerSig, Sig arbiterSig) public {
        require(checkSig(buyerSig, this.buyer));
        require(checkSig(arbiterSig, this.arbiter));
    }
}
