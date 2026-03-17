const runar = @import("runar");

/// HashToMint — Proof-of-work mineable BSV21 token with linear difficulty.
///
/// Mining puzzle: hash256(outpoint_txid || nonce) must have enough leading zero bits.
/// Difficulty ramps linearly as supply depletes — each +1 is 2x harder (bits, not nibbles).
/// The reward inscription is stored as a readonly ByteString (pre-built at deploy time).
pub const HashToMint = struct {
    pub const Contract = runar.StatefulSmartContract;

    // Mutable state (carried across transactions)
    supply: i64 = 0,

    // Readonly (embedded in compiled script)
    total_supply: i64,
    reward: i64,
    starting_difficulty: i64,
    difficulty_range: i64,
    reward_inscription: runar.ByteString,

    pub fn init(
        supply: i64,
        total_supply: i64,
        reward: i64,
        starting_difficulty: i64,
        difficulty_range: i64,
        reward_inscription: runar.ByteString,
    ) HashToMint {
        return .{
            .supply = supply,
            .total_supply = total_supply,
            .reward = reward,
            .starting_difficulty = starting_difficulty,
            .difficulty_range = difficulty_range,
            .reward_inscription = reward_inscription,
        };
    }

    pub fn redeem(self: *HashToMint, nonce: runar.ByteString, reward_pkh: runar.Addr) void {
        // SHA256d(outpoint_txid || nonce) — txid at BIP-143 preimage offset 68
        const hash = runar.hash256(runar.cat(runar.substr(self.txPreimage, 68, 32), nonce));

        // Linear difficulty ramp
        const mined = self.total_supply - self.supply;
        const diff = self.starting_difficulty + runar.mulDiv(mined, self.difficulty_range, self.total_supply);

        // Check leading zero bits byte-by-byte (unrolled)
        const b0 = runar.bin2num(runar.substr(hash, 0, 1));
        if (diff >= 8) { runar.assert(b0 == 0); }
        else if (diff >= 7) { runar.assert(b0 < 2); }
        else if (diff >= 6) { runar.assert(b0 < 4); }
        else if (diff >= 5) { runar.assert(b0 < 8); }
        else if (diff >= 4) { runar.assert(b0 < 16); }
        else if (diff >= 3) { runar.assert(b0 < 32); }
        else if (diff >= 2) { runar.assert(b0 < 64); }
        else if (diff >= 1) { runar.assert(b0 < 128); }

        const b1 = runar.bin2num(runar.substr(hash, 1, 1));
        if (diff >= 16) { runar.assert(b1 == 0); }
        else if (diff >= 15) { runar.assert(b1 < 2); }
        else if (diff >= 14) { runar.assert(b1 < 4); }
        else if (diff >= 13) { runar.assert(b1 < 8); }
        else if (diff >= 12) { runar.assert(b1 < 16); }
        else if (diff >= 11) { runar.assert(b1 < 32); }
        else if (diff >= 10) { runar.assert(b1 < 64); }
        else if (diff >= 9) { runar.assert(b1 < 128); }

        const b2 = runar.bin2num(runar.substr(hash, 2, 1));
        if (diff >= 24) { runar.assert(b2 == 0); }
        else if (diff >= 23) { runar.assert(b2 < 2); }
        else if (diff >= 22) { runar.assert(b2 < 4); }
        else if (diff >= 21) { runar.assert(b2 < 8); }
        else if (diff >= 20) { runar.assert(b2 < 16); }
        else if (diff >= 19) { runar.assert(b2 < 32); }
        else if (diff >= 18) { runar.assert(b2 < 64); }
        else if (diff >= 17) { runar.assert(b2 < 128); }

        const b3 = runar.bin2num(runar.substr(hash, 3, 1));
        if (diff >= 32) { runar.assert(b3 == 0); }
        else if (diff >= 31) { runar.assert(b3 < 2); }
        else if (diff >= 30) { runar.assert(b3 < 4); }
        else if (diff >= 29) { runar.assert(b3 < 8); }
        else if (diff >= 28) { runar.assert(b3 < 16); }
        else if (diff >= 27) { runar.assert(b3 < 32); }
        else if (diff >= 26) { runar.assert(b3 < 64); }
        else if (diff >= 25) { runar.assert(b3 < 128); }

        // Deduct reward
        runar.assert(self.supply >= self.reward);
        self.supply = self.supply - self.reward;

        // Covenant continuation
        if (self.supply > 0) {
            self.addOutput(1, self.supply);
        }

        // Reward inscription + P2PKH (covenant enforced via hashOutputs)
        const p2pkh = runar.cat(runar.cat(runar.toByteString("76a914"), reward_pkh), runar.toByteString("88ac"));
        self.addRawOutput(1, runar.cat(self.reward_inscription, p2pkh));
    }
};
