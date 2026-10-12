//! N-119 — the Zig-tier asm() array-form push() literal parser capped at
//! `i64`, refusing `push(-36893488147419103231)` ("push() argument is not a
//! valid integer literal: '36893488147419103231'") while TS and Go accept
//! it and emit identical bytes.
//!
//! Measured at HEAD: TS's `compile()` and Go's `runar-go --hex` both emit
//! `09ffffffffffffffff81` (a 9-byte LE sign-magnitude push) for
//! `push(-36893488147419103231n)` — the magnitude is 2^65 - 1, one bit past
//! `i64` range. Zig's `encodeAsmPushLiteral` (passes/parse_ts.zig) parses
//! the push() argument with `std.fmt.parseInt(i64, ..., 0)` and reports
//! ANY failure — overflow or malformed text alike — as an invalid literal,
//! so this value is refused outright.
//!
//! `opcodes.encodeScriptNumberFromDecimal` already exists for exactly this
//! case (it backs the 256-bit secp256k1 constants in the schnorr-zkp
//! fixture); the asm() array-form push() path never fell back to it on
//! `i64` overflow.
//!
//! Proves: the array-form `push(<decimal>)` literal — both the oversize
//! case this item names and the ordinary small-int case — parses clean and
//! emits the same bytes as the TS/Go reference compilers.
//!
//! Does not prove: hex-string push() arguments, non-decimal (hex-prefixed)
//! oversize literals passed to push(), or any other asm() body shape.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const parse_ts = @import("../passes/parse_ts.zig");

/// `push(-36893488147419103231n)` — magnitude 2^65 - 1, verified byte-
/// identical in the TS and Go reference compilers at HEAD.
const SOURCE =
    \\import { UnsafeSmartContract, asm } from 'runar-lang';
    \\
    \\class Probe extends UnsafeSmartContract {
    \\  constructor() {
    \\    super();
    \\  }
    \\
    \\  public unlock() {
    \\    asm({ body: [push(-36893488147419103231n)], in_arity: 0, out_arity: 1 });
    \\  }
    \\}
    \\
;

/// What the TS and Go reference compilers emit for `SOURCE` at HEAD.
const EXPECTED_HEX = "09ffffffffffffffff81";

test "N-119: asm push() of a 65-bit magnitude decimal literal parses clean" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const r = parse_ts.parseTs(alloc, SOURCE, "Probe.runar.ts");
    if (r.errors.len != 0) {
        for (r.errors) |e| std.debug.print("N-119: unexpected parse error: {s}\n", .{e});
    }
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
}

test "N-119: asm push() of a 65-bit magnitude decimal literal matches TS/Go" {
    const a = std.testing.allocator;
    const hex = try compiler_api.compileSourceToHex(a, SOURCE, "Probe.runar.ts");
    defer a.free(hex);
    try std.testing.expectEqualStrings(EXPECTED_HEX, hex);
}
