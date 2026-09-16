// R-RustBigint — the `BigintBig` type and the two wide encoder spellings on
// the Rust-DSL surface.
//
// `packages/runar-rs` gained `BigintBig` (= num_bigint::BigInt) together with
// `bin2num_big` / `num2bin_big`, because `Bigint` there is `i64` and the narrow
// pair now REFUSES a value it cannot represent rather than truncating it. A
// contract carrying a 256-bit curve coordinate therefore has to spell its type
// and its encoders the wide way.
//
// WHY THIS FILE EXISTS. The Go tier shipped exactly this API — `runar.BigintBig`
// plus `Num2BinBig` / `Bin2NumBig` — and the rewrite that makes those spellings
// mean anything lived in `compilers/go` and NOWHERE ELSE. All seven tiers parse
// every surface (CLAUDE.md invariant 1, "frontend parity, no exceptions"), so
// the other six answered `unknown function 'bin2NumBig'` and `runar.BigintBig`
// in contract source was fiction: the SDK shipped the type, the docs pointed at
// it, and the program compiled in one tier.
//
// It hid because no fixture used the spellings, and it would have kept hiding.
// Unknown-builtin is a TYPECHECK diagnostic and `--parse-only` stops after
// parse + validate, so the all-tier parser-only matrix cannot see this class at
// all. The guard has to COMPILE, which is what this corpus does.
//
// The Rust surface is in the same position for the same reason, one tier over,
// so the guard lands with the API rather than after someone trips over it.
//
// Cross-tier agreement alone would not be enough: seven tiers agreeing on a
// wrong rewrite — `num2bin_big` lowered to `bin2num`, a plausible slip — would
// pass a corpus that only compares tiers against each other. So this file has a
// peer, `RustBigintBigSpellingsRef.runar.ts`, which is the same program written
// with `bigint` and the unsuffixed encoders, and `subtype-parity.test.ts`
// requires the two to compile to ONE hex PER TIER. The suffix names a different
// Rust RUNTIME type — the mock does not truncate — not a different Script
// operation, so the bytes must be identical.
//
// Keep the two files in lockstep: same contract shape, same property, same
// method names, same parameter names, same binding names, same order. The claim
// is byte equality and any of those changes it.
use runar::prelude::*;

#[runar::contract]
struct RustBigintBigSpellings {
    // `#[readonly]`, so this is a SmartContract and not a
    // StatefulSmartContract. Without it the compiler injects checkPreimage and
    // the state continuation, the script grows by four kilobytes of OP_PUSH_TX
    // expansion, and the byte-equality claim against the stateless reference
    // becomes a claim about the injection instead of about the spellings.
    #[readonly]
    expected: BigintBig,
}

impl RustBigintBigSpellings {
    // The wide encoders, round-tripped. `num2bin_big` and `bin2num_big` must
    // emit what `num2bin` and `bin2num` emit.
    pub fn check_wide_encoders(&self, a: BigintBig) {
        let encoded = num2bin_big(a, 8);
        assert!(bin2num_big(encoded) == self.expected);
    }

    // `BigintBig` in every position a type can appear: parameter, local
    // binding, and the property above. A tier whose type table knows the name
    // in one position and not another fails here.
    pub fn check_arithmetic(&self, a: BigintBig, b: BigintBig) {
        let sum: BigintBig = a + b;
        let diff: BigintBig = a - b;
        let total: BigintBig = sum + diff;
        assert!(total == self.expected);
    }

    // Comparisons. Unlike the Go tier, this surface needs no helper functions
    // for them: num_bigint::BigInt implements PartialOrd and PartialEq, so the
    // operators are written as operators and mean what they say. Each is
    // asserted in the direction that makes it true for a < b, so any two of
    // them swapped changes the bytes.
    pub fn check_comparisons(&self, a: BigintBig, b: BigintBig) {
        assert!(a < b);
        assert!(a <= b);
        assert!(b > a);
        assert!(b >= a);
        assert!(a != b);
        assert!(a == a);
    }
}
