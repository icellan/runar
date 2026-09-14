const std = @import("std");
const runar = @import("runar");
const PriceBet = @import("PriceBet.runar.zig").PriceBet;

const contract_source = @embedFile("PriceBet.runar.zig");

test "PriceBet compiles through the Rúnar frontend" {
    const allocator = std.testing.allocator;
    const result = try runar.compileCheckSource(
        allocator,
        contract_source,
        "PriceBet.runar.zig",
    );
    defer result.deinit(allocator);
    if (!result.ok()) {
        for (result.messages) |m| std.debug.print("{s}\n", .{m});
    }
    try std.testing.expect(result.ok());
}

test "PriceBet.init stores all four constructor args" {
    const alice_pk = runar.ALICE.pubKey;
    const bob_pk = runar.BOB.pubKey;
    const oracle_pk: runar.RabinPubKey = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const c = PriceBet.init(alice_pk, bob_pk, oracle_pk, 50_000);
    try std.testing.expectEqualSlices(u8, alice_pk, c.alicePubKey);
    try std.testing.expectEqualSlices(u8, bob_pk, c.bobPubKey);
    try std.testing.expectEqualSlices(u8, oracle_pk, c.oraclePubKey);
    try std.testing.expectEqual(@as(i64, 50_000), c.strikePrice);
}

// R-215: the title of this case used to say "check_sig mock always succeeds".
// It does not — `runar.checkSig` parses the DER signature and runs a real
// secp256k1 verification against a fixed test message, so a signature made by
// the wrong key is rejected. That is what lets the settle cases below tell the
// two branches apart.
test "PriceBet.cancel requires a valid signature from each party" {
    const c = PriceBet.init(
        runar.ALICE.pubKey,
        runar.BOB.pubKey,
        &[_]u8{0},
        0,
    );
    c.cancel(runar.signTestMessage(runar.ALICE), runar.signTestMessage(runar.BOB));
}

// ---------------------------------------------------------------------------
// settle() — R-215
// ---------------------------------------------------------------------------
//
// R-215 (CL-GAP-057): this file had ZERO coverage of `settle()`, the contract's
// primary Rabin-oracle-gated method, while the other tiers test it.
//
// The proofs are real Rabin signatures over `num2bin(price, 8)` under
// `runar.testing.rabin_test_key_n`, already shipped by the SDK for exactly this
// purpose — `oraclePriceProof` returns one for 60_000, 50_000 and 30_000 and
// null otherwise, so `.?` is itself an assertion that the price being settled is
// one the oracle actually signed.
//
// EACH CASE PASSES ONLY ITS OWN BRANCH'S SIGNATURE. The other party's slot is
// filled with a signature made by the WRONG key, which `checkSig` rejects — it
// is not a blanket-true mock, it does real secp256k1 verification against a
// fixed test message. So a case passes only if the branch it names is the one
// that ran.
//
// That is load-bearing. The first version of these tests handed BOTH parties a
// valid signature, and flipping the contract's `>` to `>=` still passed all
// three — with both signatures valid, the branch taken is unobservable and the
// tests asserted only "does not panic".
//
// NOT COVERED HERE, deliberately: Go's `_ZeroPriceRejected`. `runar.assert` is
// `@panic` (assertion failure IS script-failure semantics), so a rejection case
// needs the out-of-process probe harness `examples/zig/examples_test.zig`
// provides via `expectAssertFailure`. This standalone project has none, and
// building one for a single case is a larger change than the gap it closes.

const strike: i64 = 50_000;

fn betAtStrike() PriceBet {
    return PriceBet.init(
        runar.ALICE.pubKey,
        runar.BOB.pubKey,
        &runar.testing.rabin_test_key_n,
        strike,
    );
}

test "PriceBet.settle above the strike takes the alice-wins branch" {
    const price: i64 = 60_000;
    try std.testing.expect(price > strike);
    const proof = runar.testing.oraclePriceProof(price).?;
    betAtStrike().settle(
        price,
        proof.sig,
        proof.padding,
        runar.signTestMessage(runar.ALICE),
        // Bob's slot carries ALICE's signature: valid bytes, wrong key. Only
        // the alice branch can accept this call.
        runar.signTestMessage(runar.ALICE),
    );
}

test "PriceBet.settle below the strike takes the bob-wins branch" {
    const price: i64 = 30_000;
    try std.testing.expect(price < strike);
    const proof = runar.testing.oraclePriceProof(price).?;
    betAtStrike().settle(
        price,
        proof.sig,
        proof.padding,
        // Alice's slot carries BOB's signature: valid bytes, wrong key.
        runar.signTestMessage(runar.BOB),
        runar.signTestMessage(runar.BOB),
    );
}

test "PriceBet.settle exactly at the strike takes the bob-wins branch" {
    // The boundary the contract's `>` decides: equal is NOT above, so this is
    // bob's. With `>=` the alice branch would run and reject the wrong-key
    // signature in alice's slot.
    const price: i64 = strike;
    const proof = runar.testing.oraclePriceProof(price).?;
    betAtStrike().settle(
        price,
        proof.sig,
        proof.padding,
        runar.signTestMessage(runar.BOB),
        runar.signTestMessage(runar.BOB),
    );
}
