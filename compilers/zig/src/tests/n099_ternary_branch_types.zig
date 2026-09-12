//! Port of the TypeScript reference test
//! `packages/runar-compiler/src/__tests__/n099-ternary-branch-types.test.ts`.
//!
//! N-099 — a ternary whose two arms have incompatible types.
//!
//!     const y: ByteString = f ? this.blob : x;   // blob: ByteString, x: bigint
//!
//! Measured across the seven tiers before the fix:
//!
//!     ts / rust / java          REJECT
//!     go / python / zig / ruby  ACCEPT, 12 hexchars
//!
//! This tier silently took the CONSEQUENT's type as the expression's type. A
//! ByteString and a bigint do not share a stack representation — one is a byte
//! string, the other a script number — so the arm that was silently retyped
//! leaves the wrong kind of value on the stack and everything downstream reads
//! a type the author never wrote. Same class as the operand-position
//! `<unknown>` escapes R-092 closed: a 33-byte push into an arithmetic opcode
//! succeeds post-Genesis and computes something meaningless rather than
//! failing.
//!
//! The fall-through this rule needs was already here — `isSubtype(alt, cons)`
//! then `isSubtype(cons, alt)` — it returned `cons_type` from it instead of
//! raising. Ported from the TypeScript reference (Rust carries it verbatim),
//! wording included. The neighbouring "ternary condition must be boolean"
//! message is lowercase in this tier's house style while TS capitalises it;
//! that pre-existing casing divergence is left alone, and the NEW message
//! matches TS exactly so the seven tiers agree on it.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");
const compiler_api = @import("../compiler_api.zig");

const HEAD =
    \\import { SmartContract, ByteString, Ripemd160, assert, hash160 } from 'runar-lang';
    \\class C extends SmartContract {
    \\  readonly pkh: Ripemd160;
    \\  readonly blob: ByteString;
    \\  constructor(pkh: Ripemd160, blob: ByteString) {
    \\    super(pkh, blob);
    \\    this.pkh = pkh;
    \\    this.blob = blob;
    \\  }
    \\  private anySats(): bigint { return 1n; }
    \\
;

// --- REJECT ----------------------------------------------------------------

const MIXED_ARMS = HEAD ++
    \\  public go(x: bigint, f: boolean) {
    \\    const y: ByteString = f ? this.blob : x;
    \\    assert(y == this.blob);
    \\  }
    \\}
;

/// The mirror image. A rule that only looked one way would let this through.
const MIXED_ARMS_SWAPPED = HEAD ++
    \\  public go(x: bigint, f: boolean) {
    \\    const y: bigint = f ? x : this.blob;
    \\    assert(y > 0n);
    \\  }
    \\}
;

// --- ACCEPT (over-rejection guards) ----------------------------------------

const SAME_TYPE_ARMS = HEAD ++
    \\  public go(x: bigint, f: boolean) {
    \\    const a: bigint = f ? x : 2n;
    \\    assert(a > 0n);
    \\  }
    \\}
;

/// `Ripemd160` is a declared subtype of `ByteString`; isSubtype relates them
/// and the rule must not fire.
const SUBTYPE_ARMS = HEAD ++
    \\  public go(x: bigint, f: boolean) {
    \\    const b: ByteString = f ? this.blob : this.pkh;
    \\    assert(hash160(b) != this.pkh || x > 0n);
    \\  }
    \\}
;

/// A private helper's declared return type is discarded at parse time in EVERY
/// tier, so this arm infers as `unknown` — top of the subtype lattice, hence
/// related to everything. Must stay ACCEPTED.
const UNKNOWN_ARM = HEAD ++
    \\  public go(x: bigint, f: boolean) {
    \\    const c: bigint = f ? this.anySats() : x;
    \\    assert(c > 0n);
    \\  }
    \\}
;

// ---------------------------------------------------------------------------

/// Parse + typecheck a `.runar.ts` source and report whether any TYPE-CHECK
/// error contains `needle`. A parse failure is surfaced as an error rather than
/// silently counted as a rejection.
fn typecheckHasError(a: std.mem.Allocator, src: []const u8, needle: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();

    const parsed = parse_ts.parseTs(w, src, "C.runar.ts");
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    const contract = parsed.contract orelse return error.TestFixtureDidNotParse;

    const result = try typecheck.typeCheck(w, contract);
    for (result.errors) |msg| {
        if (std.mem.indexOf(u8, msg, needle) != null) return true;
    }
    return false;
}

test "N-099: incompatible ternary arms are rejected" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        MIXED_ARMS,
        "Ternary branches have incompatible types: 'ByteString' and 'bigint'",
    ));
    try std.testing.expectError(
        error.TypeCheckFailed,
        compiler_api.compileSource(a, MIXED_ARMS, "C.runar.ts"),
    );
}

test "N-099: the swapped shape is rejected too" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        MIXED_ARMS_SWAPPED,
        "Ternary branches have incompatible types: 'bigint' and 'ByteString'",
    ));
}

test "N-099: legal ternary arms still compile" {
    const a = std.testing.allocator;
    for ([_][]const u8{ SAME_TYPE_ARMS, SUBTYPE_ARMS, UNKNOWN_ARM }) |src| {
        const result = try compiler_api.compileSource(a, src, "C.runar.ts");
        if (result.artifact_json) |j| a.free(j);
        defer a.free(result.script_hex);
        try std.testing.expect(result.script_hex.len > 0);
    }
}
