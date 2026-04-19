const runar = @import("runar");

/// PriceBet — a two-party price wager settled by a Rabin oracle.
///
/// Oracle replay note: The oracle signs only num2bin(price, 8) — raw price
/// bytes with no domain separation. Any valid oracle signature for a given
/// price can be reused across all PriceBet contracts that share the same
/// oraclePubKey. This is acceptable when oracle attestations represent
/// reusable global facts (e.g., "BTC price at block N"). For production
/// contracts requiring per-instance isolation, include domain fields such
/// as a contract ID, UTXO outpoint, or expiry timestamp in the signed
/// message.
///
/// Mirrors the reference variants in
/// examples/end2end-example/{ts,go,rust,ruby,python}/PriceBet.runar.*.
pub const PriceBet = struct {
    pub const Contract = runar.SmartContract;

    alicePubKey: runar.PubKey,
    bobPubKey: runar.PubKey,
    oraclePubKey: runar.RabinPubKey,
    strikePrice: i64,

    pub fn init(
        alicePubKey: runar.PubKey,
        bobPubKey: runar.PubKey,
        oraclePubKey: runar.RabinPubKey,
        strikePrice: i64,
    ) PriceBet {
        return .{
            .alicePubKey = alicePubKey,
            .bobPubKey = bobPubKey,
            .oraclePubKey = oraclePubKey,
            .strikePrice = strikePrice,
        };
    }

    pub fn settle(
        self: *const PriceBet,
        price: i64,
        rabinSig: runar.RabinSig,
        padding: runar.ByteString,
        aliceSig: runar.Sig,
        bobSig: runar.Sig,
    ) void {
        const msg = runar.num2bin(price, 8);
        runar.assert(runar.verifyRabinSig(msg, rabinSig, padding, self.oraclePubKey));
        runar.assert(price > 0);
        if (price > self.strikePrice) {
            // bobSig is present in the unlocking script for stack alignment
            // but is intentionally not checked in this branch — alice wins.
            runar.assert(runar.checkSig(aliceSig, self.alicePubKey));
        } else {
            // aliceSig is present in the unlocking script for stack alignment
            // but is intentionally not checked in this branch — bob wins.
            runar.assert(runar.checkSig(bobSig, self.bobPubKey));
        }
    }

    pub fn cancel(self: *const PriceBet, aliceSig: runar.Sig, bobSig: runar.Sig) void {
        runar.assert(runar.checkSig(aliceSig, self.alicePubKey));
        runar.assert(runar.checkSig(bobSig, self.bobPubKey));
    }
};
