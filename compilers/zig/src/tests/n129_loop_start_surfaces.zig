//! N-129 — the `.runar.go` and `.runar.java` for-loop parsers dropped the
//! loop's INIT VALUE, so every loop started at 0.
//!
//! Both parsers extracted the init value only when the token was a bare number.
//! Neither surface writes one: the loop variable is a wrapped integer, so the
//! idiomatic spellings are `for i := runar.Int(3)` and
//! `for (Bigint i = Bigint.of(3); ...)`. Both fell into an `else` branch that
//! parsed the expression and THREW IT AWAY, leaving `init_value = 0`.
//!
//! The count is derived from the bound, so the damage is not a shifted loop —
//! it is a different number of iterations over different values:
//!
//!     for i := runar.Int(3); i < 7; i++   {acc += i}
//!         source says   3 + 4 + 5 + 6         = 18   (0x12)
//!         this tier     0 + 1 + 2 + 3 + 4 + 5 + 6 = 21  (0x15)
//!
//! Six tiers produced 18 from the same file; this one produced 21. A contract
//! whose assert compares against 18 is unspendable when compiled here, and one
//! comparing against 21 is spendable when it should not be — the direction
//! depends on the contract, which is what makes a wrong-value miscompile worse
//! than a crash.
//!
//! It survived because the corpus had no non-zero-start loop anywhere (R-102):
//! two `for` loops repo-wide, both starting at 0, where the bug is invisible.
//! The `loop-shapes` conformance fixture landed with this fix closes that.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// The `.runar.go` spelling of a non-zero start.
const GO_SOURCE =
    \\//go:build ignore
    \\
    \\package contract
    \\
    \\import "runar"
    \\
    \\type LoopStart struct {
    \\    runar.SmartContract
    \\    Target runar.Int `runar:"readonly"`
    \\}
    \\
    \\func (c *LoopStart) Verify(seed runar.Int) {
    \\    acc := seed
    \\    for i := runar.Int(3); i < 7; i++ {
    \\        acc = acc + i
    \\    }
    \\    runar.Assert(acc == c.Target)
    \\}
;

/// The `.runar.java` spelling of the same loop.
const JAVA_SOURCE =
    \\package runar.examples.loopstart;
    \\
    \\import runar.lang.SmartContract;
    \\import runar.lang.annotations.Public;
    \\import runar.lang.annotations.Readonly;
    \\import runar.lang.types.Bigint;
    \\
    \\import static runar.lang.Builtins.assertThat;
    \\
    \\class LoopStart extends SmartContract {
    \\
    \\    @Readonly Bigint target;
    \\
    \\    LoopStart(Bigint target) {
    \\        super(target);
    \\        this.target = target;
    \\    }
    \\
    \\    @Public
    \\    void verify(Bigint seed) {
    \\        Bigint acc = seed;
    \\        for (Bigint i = Bigint.of(3); i.lt(Bigint.of(7)); i = i.plus(Bigint.ONE)) {
    \\            acc = acc.plus(i);
    \\        }
    \\        assertThat(acc.eq(this.target));
    \\    }
    \\}
;

/// The `.runar.ts` spelling, which never had the bug — the control.
const TS_SOURCE =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\export class LoopStart extends SmartContract {
    \\  readonly target: bigint;
    \\
    \\  constructor(target: bigint) {
    \\    super(target);
    \\    this.target = target;
    \\  }
    \\
    \\  public verify(seed: bigint) {
    \\    let acc: bigint = seed;
    \\    for (let i = 3n; i < 7n; i++) {
    \\      acc = acc + i;
    \\    }
    \\    assert(acc === this.target);
    \\  }
    \\}
;

/// `3 + 4 + 5 + 6 = 18`, folded to a single push of 0x12, then OP_ADD against
/// the seed and OP_NUMEQUAL against the constructor slot.
const EXPECTED_HEX = "011293009c";

fn compileHex(a: std.mem.Allocator, src: []const u8, file_name: []const u8) ![]const u8 {
    const result = try compiler_api.compileSource(a, src, file_name);
    if (result.artifact_json) |j| a.free(j);
    return result.script_hex;
}

test "N-129: a non-zero loop start survives the .runar.go parser" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, GO_SOURCE, "LoopStart.runar.go");
    defer a.free(hex);
    try std.testing.expectEqualStrings(EXPECTED_HEX, hex);
}

test "N-129: a non-zero loop start survives the .runar.java parser" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, JAVA_SOURCE, "LoopStart.runar.java");
    defer a.free(hex);
    try std.testing.expectEqualStrings(EXPECTED_HEX, hex);
}

test "N-129: the control surface agrees, so the expectation is not tier-local" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, TS_SOURCE, "LoopStart.runar.ts");
    defer a.free(hex);
    try std.testing.expectEqualStrings(EXPECTED_HEX, hex);
}

test "N-129: all three surfaces agree with each other" {
    const a = std.testing.allocator;
    const go_hex = try compileHex(a, GO_SOURCE, "LoopStart.runar.go");
    defer a.free(go_hex);
    const java_hex = try compileHex(a, JAVA_SOURCE, "LoopStart.runar.java");
    defer a.free(java_hex);
    const ts_hex = try compileHex(a, TS_SOURCE, "LoopStart.runar.ts");
    defer a.free(ts_hex);

    try std.testing.expectEqualStrings(ts_hex, go_hex);
    try std.testing.expectEqualStrings(ts_hex, java_hex);
}
