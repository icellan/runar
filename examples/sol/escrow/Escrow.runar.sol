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

    function releaseBySeller(Sig sig) public {
        require(checkSig(sig, this.seller));
    }

    function releaseByArbiter(Sig sig) public {
        require(checkSig(sig, this.arbiter));
    }

    function refundToBuyer(Sig sig) public {
        require(checkSig(sig, this.buyer));
    }

    function refundByArbiter(Sig sig) public {
        require(checkSig(sig, this.arbiter));
    }
}
