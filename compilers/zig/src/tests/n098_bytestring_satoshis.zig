//! Port of the TypeScript reference test
//! `packages/runar-compiler/src/__tests__/n098-bytestring-satoshis.test.ts`.
//!
//! N-098 — a ByteString in the SATOSHIS position of an output intrinsic.
//!
//! This tier ACCEPTED all three shapes. It was not a missing diagnostic: the
//! ByteString was lowered into the satoshis slot with NO conversion, and the
//! emitted script was byte-identical to the same contract written with
//! `blob: bigint` — 1358 hexchars, same digest, in all six accepting tiers.
//!
//! `lowerAddOutput` prepends the satoshis operand as `OP_8 OP_NUM2BIN`, so the
//! covenant commits to whatever those bytes decode to as a script number.
//! Executed on the real @bsv/sdk Spend engine with `blob = 0x2a`, a 42-satoshi
//! continuation VALIDATES and the 1000-satoshi one the author funded is
//! REJECTED. Bigger blobs fail shut rather than safe: 0xcafebabefeed0001
//! demands 7.2e16 satoshis and a 20-byte hash aborts the script at
//! OP_NUM2BIN, leaving the UTXO permanently unspendable.
//!
//! The rule ported here is the TypeScript reference's, wording included. Only
//! the FIRST argument is checked. TS additionally checks arity, the state-value
//! types and the scriptBytes argument; none of those are ported here and none
//! of them are this finding.
//!
//! The ACCEPT block carries the real risk in a change like this. `<unknown>`
//! must stay accepted: a private helper's declared return type is discarded at
//! parse time in every tier, so `this.sats()` infers as `<unknown>`, and TS has
//! always escaped it here.
//!
//! Note this tier spells the type `unknown`, not `<unknown>` (RunarType is an
//! enum, and `runarTypeToString` has always printed it bare). That predates
//! this finding and is left alone — the rejection-parity gate grades the
//! verdict, and the substring asserted below is the part the seven tiers share.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");
const compiler_api = @import("../compiler_api.zig");

const HEAD =
    \\import { StatefulSmartContract, ByteString, assert } from 'runar-lang';
    \\class C extends StatefulSmartContract {
    \\  count: bigint;
    \\  readonly base: bigint;
    \\  readonly blob: ByteString;
    \\  constructor(count: bigint, base: bigint, blob: ByteString) {
    \\    super(count, base, blob);
    \\    this.count = count;
    \\    this.base = base;
    \\    this.blob = blob;
    \\  }
    \\  private sats(): bigint { return this.base; }
    \\
;

// --- REJECT ----------------------------------------------------------------

const ADD_OUTPUT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(this.blob, this.count);
    \\  }
    \\}
;

const ADD_RAW_OUTPUT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addRawOutput(this.blob, this.blob);
    \\  }
    \\}
;

const ADD_DATA_OUTPUT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addDataOutput(this.blob, this.blob);
    \\  }
    \\}
;

// --- ACCEPT (over-rejection guards) ----------------------------------------

const LITERAL_SATS = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\  }
    \\}
;

const PARAM_SATS = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(n, this.count);
    \\  }
    \\}
;

const PROPERTY_SATS = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(this.base, this.count);
    \\  }
    \\}
;

/// A private helper's declared return type is discarded at parse time in EVERY
/// tier, so this infers as `unknown`. It must stay ACCEPTED.
const HELPER_SATS = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(this.sats(), this.count);
    \\  }
    \\}
;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse + typecheck a `.runar.ts` source and report whether any TYPE-CHECK
/// error contains `needle`. A parse failure is surfaced as an error rather than
/// silently counted as a rejection — a fixture refused for the wrong reason
/// would make this file vacuous.
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

/// Compile end-to-end and hand back the locking-script hex (caller frees).
fn compileHex(a: std.mem.Allocator, src: []const u8) ![]const u8 {
    const result = try compiler_api.compileSource(a, src, "C.runar.ts");
    if (result.artifact_json) |j| a.free(j);
    return result.script_hex;
}

// ---------------------------------------------------------------------------
// The defect
// ---------------------------------------------------------------------------

test "N-098: addOutput rejects a ByteString first argument" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        ADD_OUTPUT,
        "addOutput() first argument (satoshis) must be bigint, got 'ByteString'",
    ));
    try std.testing.expectError(error.TypeCheckFailed, compiler_api.compileSource(a, ADD_OUTPUT, "C.runar.ts"));
}

test "N-098: addRawOutput rejects a ByteString first argument" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        ADD_RAW_OUTPUT,
        "addRawOutput() first argument (satoshis) must be bigint, got 'ByteString'",
    ));
}

test "N-098: addDataOutput rejects a ByteString first argument" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        ADD_DATA_OUTPUT,
        "addDataOutput() first argument (satoshis) must be bigint, got 'ByteString'",
    ));
}

// ---------------------------------------------------------------------------
// Controls — the legal satoshis positions must stay accepted
// ---------------------------------------------------------------------------

test "N-098: accepted satoshis positions still compile" {
    const a = std.testing.allocator;
    for ([_][]const u8{ LITERAL_SATS, PARAM_SATS, PROPERTY_SATS, HELPER_SATS }) |src| {
        const hex = try compileHex(a, src);
        defer a.free(hex);
        try std.testing.expect(hex.len > 0);
    }
}

// Non-vacuity: "it compiled" would also hold for a tier that discarded the
// satoshis operand entirely. A literal and a runtime parameter must lower to
// DIFFERENT scripts. Every tier's own N-098 test makes this same assertion.
test "N-098: the satoshis operand reaches codegen" {
    const a = std.testing.allocator;
    const lit = try compileHex(a, LITERAL_SATS);
    defer a.free(lit);
    const param = try compileHex(a, PARAM_SATS);
    defer a.free(param);
    try std.testing.expect(!std.mem.eql(u8, lit, param));
    // PUSH(2) 0xe8 0x03 == 1000
    try std.testing.expect(std.mem.indexOf(u8, lit, "02e803") != null);
}
