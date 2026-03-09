// OraclePriceFeed — A stateless oracle contract for price-triggered payouts.
//
// Demonstrates the "oracle pattern" where off-chain data (e.g., asset prices)
// is cryptographically signed by a trusted oracle and verified on-chain using
// Rabin signatures. Rabin signatures are well-suited for Bitcoin Script because
// verification requires only modular multiplication and comparison — operations
// that are cheap in Script.
//
// The contract enforces three verification layers:
//   1. Oracle verification — the price was genuinely signed by the trusted oracle's Rabin key
//   2. Price threshold — the price must exceed 50,000 (application-specific business logic)
//   3. Receiver authorization — the receiver must provide a valid ECDSA signature
//
// Use cases: derivatives/futures settlement, price-triggered payouts, conditional
// escrow based on market data, insurance contracts.
//
// Contract model: Stateless (SmartContract). The oracle's Rabin public key and the
// receiver's ECDSA public key are immutable constructor parameters.
module OraclePriceFeed {
    use runar::types::{PubKey, Sig, ByteString, RabinSig, RabinPubKey};
    use runar::crypto::{check_sig, verify_rabin_sig, num2bin};

    resource struct OraclePriceFeed {
        // Rabin public key of the trusted oracle (a large integer modulus, typically 128+ bytes).
        oracle_pub_key: RabinPubKey,
        // ECDSA compressed public key (33 bytes) of the authorized payout receiver.
        receiver: PubKey,
    }

    // Settle the contract by proving a price was signed by the oracle and exceeds
    // the threshold. The receiver must also sign to authorize the payout.
    //
    // Parameters:
    //   price     - The oracle-attested price value (integer).
    //   rabin_sig - Rabin signature produced by the oracle over the price (variable length).
    //   padding   - Rabin signature padding bytes required for verification (variable length).
    //   sig       - ECDSA signature (~72 bytes) from the receiver authorizing the spend.
    public fun settle(contract: &OraclePriceFeed, price: bigint, rabin_sig: RabinSig, padding: ByteString, sig: Sig) {
        // Layer 1: Oracle verification — convert the price to its 8-byte little-endian
        // canonical form (the format the oracle signs), then verify the Rabin signature
        // against the oracle's public key using modular arithmetic.
        let msg = num2bin(price, 8);
        assert!(verify_rabin_sig(msg, rabin_sig, padding, contract.oracle_pub_key), 0);

        // Layer 2: Price threshold — application-specific business logic requiring
        // the oracle-attested price to exceed 50,000 before the payout is allowed.
        assert!(price > 50000, 0);

        // Layer 3: Receiver authorization — the designated receiver must provide a
        // valid ECDSA signature to claim the payout, preventing front-running.
        assert!(check_sig(sig, contract.receiver), 0);
    }
}
