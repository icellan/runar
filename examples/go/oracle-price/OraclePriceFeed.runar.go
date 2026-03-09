package contract

import runar "github.com/icellan/runar/packages/runar-go"

// OraclePriceFeed is a stateless oracle contract for price-triggered payouts.
//
// It demonstrates the "oracle pattern" where off-chain data (e.g., asset prices)
// is cryptographically signed by a trusted oracle and verified on-chain using
// Rabin signatures. Rabin signatures are well-suited for Bitcoin Script because
// verification requires only modular multiplication and comparison — operations
// that are cheap in Script.
//
// The contract enforces three verification layers:
//   1. Oracle verification — the price was genuinely signed by the trusted oracle's Rabin key
//   2. Price threshold — the price must exceed 50,000 (application-specific business logic)
//   3. Receiver authorization — the receiver must provide a valid ECDSA signature to claim the payout
//
// Use cases: derivatives/futures settlement, price-triggered payouts, conditional
// escrow based on market data, insurance contracts.
//
// Contract model: Stateless (SmartContract). The oracle's Rabin public key and the
// receiver's ECDSA public key are immutable constructor parameters.
type OraclePriceFeed struct {
	runar.SmartContract
	// OraclePubKey is the Rabin public key of the trusted oracle (a large integer
	// modulus, typically 128+ bytes).
	OraclePubKey runar.RabinPubKey `runar:"readonly"`
	// Receiver is the ECDSA compressed public key (33 bytes) of the authorized
	// payout receiver.
	Receiver runar.PubKey `runar:"readonly"`
}

// Settle verifies that an oracle-attested price exceeds the threshold and that
// the receiver authorizes the spend.
//
// Parameters:
//   - price:    the oracle-attested price value (integer)
//   - rabinSig: Rabin signature produced by the oracle over the price (variable length)
//   - padding:  Rabin signature padding bytes required for verification (variable length)
//   - sig:      ECDSA signature (~72 bytes) from the receiver authorizing the spend
func (c *OraclePriceFeed) Settle(price runar.Bigint, rabinSig runar.RabinSig, padding runar.ByteString, sig runar.Sig) {
	// Layer 1: Oracle verification — convert the price to its 8-byte little-endian
	// canonical form (the format the oracle signs), then verify the Rabin signature
	// against the oracle's public key using modular arithmetic.
	msg := runar.Num2Bin(price, 8)

	runar.Assert(runar.VerifyRabinSig(msg, rabinSig, padding, c.OraclePubKey))

	// Layer 2: Price threshold — application-specific business logic requiring
	// the oracle-attested price to exceed 50,000 before the payout is allowed.
	runar.Assert(price > 50000)

	// Layer 3: Receiver authorization — the designated receiver must provide a
	// valid ECDSA signature to claim the payout, preventing front-running.
	runar.Assert(runar.CheckSig(sig, c.Receiver))
}
