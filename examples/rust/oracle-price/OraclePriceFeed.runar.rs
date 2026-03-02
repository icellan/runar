use runar::prelude::*;

#[runar::contract]
pub struct OraclePriceFeed {
    #[readonly]
    pub oracle_pub_key: RabinPubKey,
    #[readonly]
    pub receiver: PubKey,
}

#[runar::methods(OraclePriceFeed)]
impl OraclePriceFeed {
    #[public]
    pub fn settle(&self, price: Bigint, rabin_sig: &RabinSig, padding: &ByteString, sig: &Sig) {
        let msg = num2bin(&price, 8);
        assert!(verify_rabin_sig(&msg, rabin_sig, padding, &self.oracle_pub_key));
        assert!(price > 50000);
        assert!(check_sig(sig, &self.receiver));
    }
}
