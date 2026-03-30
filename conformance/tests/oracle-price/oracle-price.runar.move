module OraclePriceFeed {
    use runar::types::{PubKey, Sig, ByteString, RabinSig, RabinPubKey};
    use runar::crypto::{check_sig, verify_rabin_sig, num2bin};

    struct OraclePriceFeed {
        oracle_pub_key: RabinPubKey,
        receiver: PubKey,
    }

    public fun settle(contract: &OraclePriceFeed, price: bigint, rabin_sig: RabinSig, padding: ByteString, sig: Sig) {
        // Verify oracle signed this price
        let msg = num2bin(price, 8);
        assert!(verify_rabin_sig(msg, rabin_sig, padding, contract.oracle_pub_key), 0);

        // Price must be above threshold for payout
        assert!(price > 50000, 0);

        // Receiver must sign
        assert!(check_sig(sig, contract.receiver), 0);
    }
}
