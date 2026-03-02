pragma runar ^0.1.0;

contract OraclePriceFeed is SmartContract {
    RabinPubKey immutable oraclePubKey;
    PubKey immutable receiver;

    constructor(RabinPubKey _oraclePubKey, PubKey _receiver) {
        oraclePubKey = _oraclePubKey;
        receiver = _receiver;
    }

    function settle(bigint price, RabinSig rabinSig, ByteString padding, Sig sig) public {
        // Verify oracle signed this price
        let ByteString msg = num2bin(price, 8);
        require(verifyRabinSig(msg, rabinSig, padding, this.oraclePubKey));

        // Price must be above threshold for payout
        require(price > 50000);

        // Receiver must sign
        require(checkSig(sig, this.receiver));
    }
}
