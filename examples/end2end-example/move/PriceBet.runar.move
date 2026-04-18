module PriceBet {
    use runar::types::{PubKey, Sig, ByteString, RabinSig, RabinPubKey};
    use runar::crypto::{check_sig, verify_rabin_sig, num2bin};

    resource struct PriceBet {
        alice_pub_key: PubKey,
        bob_pub_key: PubKey,
        oracle_pub_key: RabinPubKey,
        strike_price: bigint,
    }

    public fun settle(contract: &PriceBet, price: bigint, rabin_sig: RabinSig, padding: ByteString, alice_sig: Sig, bob_sig: Sig) {
        let msg = num2bin(price, 8);
        assert!(verify_rabin_sig(msg, rabin_sig, padding, contract.oracle_pub_key), 0);

        assert!(price > 0, 0);

        if (price > contract.strike_price) {
            // bob_sig is present in the unlocking script for stack alignment but is
            // intentionally not checked in this branch — only alice (the winner) signs.
            assert!(check_sig(alice_sig, contract.alice_pub_key), 0);
        } else {
            // alice_sig is present in the unlocking script for stack alignment but is
            // intentionally not checked in this branch — only bob (the winner) signs.
            assert!(check_sig(bob_sig, contract.bob_pub_key), 0);
        }
    }

    public fun cancel(contract: &PriceBet, alice_sig: Sig, bob_sig: Sig) {
        assert!(check_sig(alice_sig, contract.alice_pub_key), 0);
        assert!(check_sig(bob_sig, contract.bob_pub_key), 0);
    }
}
