use runar::prelude::*;

#[runar::contract]
struct OraclePriceFeed {
    #[readonly]
    oracle_pub_key: RabinPubKey,
    #[readonly]
    receiver: PubKey,
}

#[runar::methods(OraclePriceFeed)]
impl OraclePriceFeed {
    #[public]
    fn settle(&self, price: Bigint, rabin_sig: &RabinSig, padding: &ByteString, sig: &Sig) {
        // Verify oracle signed this price
        let msg = num2bin(&price, 8);
        assert!(verify_rabin_sig(&msg, rabin_sig, padding, &self.oracle_pub_key));

        // Price must be above threshold for payout
        assert!(price > 50000);

        // Receiver must sign
        assert!(check_sig(sig, &self.receiver));
    }
}
