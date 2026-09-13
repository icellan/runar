//! N-134 — every Zig-tier surface parser rejected an oversize HEX literal,
//! while accepting the same value written in decimal.
//!
//! The integer-literal path in each parser tries `parseInt(i64, text, 0)` and,
//! on failure, keeps the text as a `literal_bigint` only when it
//! `isAllAsciiDigits`. A 256-bit literal written `0xFFFF…41n` — the ordinary
//! way to write the secp256k1 group order, and the way `EC_N` and every curve
//! bound is spelled — is not all digits, so it fell through to
//! `invalid integer` and the file did not parse at all.
//!
//! Six tiers compile that source; this one refused it. That is a breach of the
//! project's first invariant (every tier parses every surface), and the failure
//! mode is the worst kind for a parity suite: not a divergent script, an
//! absent one — so a cross-tier comparison never even gets a value from this
//! tier to disagree with.
//!
//! Measured on `assert(x < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n && x > this.a)`:
//!
//!     go / rust / python / ruby   7621414136d08c…9f6300a067007768   (hex spelling)
//!     go / rust / python / ruby   7621414136d08c…9f6300a067007768   (decimal spelling)
//!     zig                          parse error: invalid integer     (hex spelling)
//!     zig                         7621414136d08c…9f6300a067007768   (decimal spelling)
//!
//! The fix converts an oversize literal in ANY radix to its canonical decimal
//! text, which is the form `literal_bigint` already carries through ANF, IR
//! JSON and codegen. The equality this file asserts is the real property: the
//! two spellings of one number must compile to one script.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// secp256k1's group order, written the way a contract author writes it.
const HEX_SOURCE =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\export class HexBigLiteral extends SmartContract {
    \\  readonly a: bigint;
    \\
    \\  constructor(a: bigint) {
    \\    super(a);
    \\    this.a = a;
    \\  }
    \\
    \\  public go(x: bigint) {
    \\    assert(x < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n && x > this.a);
    \\  }
    \\}
;

/// The same number in decimal — the spelling this tier already accepted.
const DEC_SOURCE =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\export class HexBigLiteral extends SmartContract {
    \\  readonly a: bigint;
    \\
    \\  constructor(a: bigint) {
    \\    super(a);
    \\    this.a = a;
    \\  }
    \\
    \\  public go(x: bigint) {
    \\    assert(x < 115792089237316195423570985008687907852837564279074904382605163141518161494337n && x > this.a);
    \\  }
    \\}
;

/// What go, rust, python and ruby emit for BOTH spellings.
const EXPECTED_HEX = "7621414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff009f6300a067007768";

fn compileHex(a: std.mem.Allocator, src: []const u8, file_name: []const u8) ![]const u8 {
    const result = try compiler_api.compileSource(a, src, file_name);
    if (result.artifact_json) |j| a.free(j);
    return result.script_hex;
}

test "N-134: an oversize hex literal parses and compiles" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, HEX_SOURCE, "HexBigLiteral.runar.ts");
    defer a.free(hex);
    try std.testing.expectEqualStrings(EXPECTED_HEX, hex);
}

test "N-134: the decimal spelling still compiles, unchanged" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, DEC_SOURCE, "HexBigLiteral.runar.ts");
    defer a.free(hex);
    try std.testing.expectEqualStrings(EXPECTED_HEX, hex);
}

test "N-134: the two spellings of one number compile to one script" {
    const a = std.testing.allocator;
    const hex_form = try compileHex(a, HEX_SOURCE, "HexBigLiteral.runar.ts");
    defer a.free(hex_form);
    const dec_form = try compileHex(a, DEC_SOURCE, "HexBigLiteral.runar.ts");
    defer a.free(dec_form);
    try std.testing.expectEqualStrings(dec_form, hex_form);
}
