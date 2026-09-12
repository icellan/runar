//! Port of the TypeScript reference test
//! `packages/runar-compiler/src/__tests__/n105-scriptbytes.test.ts`.
//!
//! N-105 (1/2) — a NUMBER in the scriptBytes position of addRawOutput /
//! addDataOutput.
//!
//! Same shape as N-098, one argument slot over, and the slot is the created
//! output's LOCKING SCRIPT.
//!
//! This tier ACCEPTED `this.addRawOutput(1000n, n)` with `n: bigint`, and the
//! emitted script was byte-identical to the same contract written with
//! `n: ByteString` — measured, same digest, in all six accepting tiers. The
//! operand is not converted: whatever sits in that slot is spliced into the
//! output serialization as the output's script.
//!
//! `lowerAddRawOutput` takes OP_SIZE of the operand, varint-prefixes it and
//! concatenates it after the 8-byte amount. A script NUMBER on the stack is its
//! minimal little-endian encoding, so the covenant commits to an output whose
//! locking script IS those bytes. Executed on the real @bsv/sdk Spend engine
//! against the exact 55-opcode window all six tiers emit:
//!
//!   n=0     -> scriptLen 0   locking script (empty)     — anyone-can-spend
//!   n=81    -> scriptLen 1   0x51 = OP_1                — anyone-can-spend
//!   n=118   -> scriptLen 1   0x76 = OP_DUP              — anyone-can-spend
//!   n=1000  -> scriptLen 2   0xe8 0x03, 0xe8 invalid    — unspendable
//!
//! N-098's failure mode was a wrong amount or a frozen UTXO. This one can hand
//! the whole output to anybody who sees it, which is why it is a gate.
//!
//! Ported from the TypeScript reference, wording included. `<unknown>` stays
//! ACCEPTED exactly as TS has it — a private helper's declared return type is
//! discarded at parse time in every tier.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");
const compiler_api = @import("../compiler_api.zig");

const HEAD =
    \\import { StatefulSmartContract, ByteString, Ripemd160, assert } from 'runar-lang';
    \\class C extends StatefulSmartContract {
    \\  count: bigint;
    \\  readonly base: bigint;
    \\  readonly flag: boolean;
    \\  readonly blob: ByteString;
    \\  readonly pkh: Ripemd160;
    \\  constructor(count: bigint, base: bigint, flag: boolean, blob: ByteString, pkh: Ripemd160) {
    \\    super(count, base, flag, blob, pkh);
    \\    this.count = count;
    \\    this.base = base;
    \\    this.flag = flag;
    \\    this.blob = blob;
    \\    this.pkh = pkh;
    \\  }
    \\  private bytes(): ByteString { return this.blob; }
    \\
;

// --- REJECT ----------------------------------------------------------------

const RAW_BIGINT_SCRIPT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addRawOutput(500n, this.base);
    \\  }
    \\}
;

const DATA_BIGINT_SCRIPT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addDataOutput(500n, this.base);
    \\  }
    \\}
;

const RAW_BOOLEAN_SCRIPT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addRawOutput(500n, this.flag);
    \\  }
    \\}
;

// --- ACCEPT (over-rejection guards) ----------------------------------------

const RAW_BYTESTRING_SCRIPT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addRawOutput(500n, this.blob);
    \\  }
    \\}
;

const RAW_STATE_SCRIPT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addRawOutput(500n, this.getStateScript());
    \\  }
    \\}
;

/// A ByteString SUBTYPE. TS's rule is `isSubtype(scriptType, ByteString)`, not
/// equality, so Ripemd160 must keep compiling.
const RAW_SUBTYPE_SCRIPT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addRawOutput(500n, this.pkh);
    \\  }
    \\}
;

/// A private helper's declared return type is discarded at parse time in every
/// tier, so this infers as unknown. TS escapes it; every port must too.
const RAW_HELPER_SCRIPT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addRawOutput(500n, this.bytes());
    \\  }
    \\}
;

const DATA_BYTESTRING_SCRIPT = HEAD ++
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addDataOutput(500n, this.blob);
    \\  }
    \\}
;

// ---------------------------------------------------------------------------
// Helpers
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

fn compileHex(a: std.mem.Allocator, src: []const u8) ![]const u8 {
    const result = try compiler_api.compileSource(a, src, "C.runar.ts");
    if (result.artifact_json) |j| a.free(j);
    return result.script_hex;
}

// ---------------------------------------------------------------------------
// The defect
// ---------------------------------------------------------------------------

test "N-105: addRawOutput rejects a bigint scriptBytes argument" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        RAW_BIGINT_SCRIPT,
        "addRawOutput() second argument (scriptBytes) must be ByteString, got 'bigint'",
    ));
    try std.testing.expectError(
        error.TypeCheckFailed,
        compiler_api.compileSource(a, RAW_BIGINT_SCRIPT, "C.runar.ts"),
    );
}

test "N-105: addDataOutput rejects a bigint scriptBytes argument" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        DATA_BIGINT_SCRIPT,
        "addDataOutput() second argument (scriptBytes) must be ByteString, got 'bigint'",
    ));
}

test "N-105: addRawOutput rejects a boolean scriptBytes argument" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        RAW_BOOLEAN_SCRIPT,
        "addRawOutput() second argument (scriptBytes) must be ByteString, got 'boolean'",
    ));
}

// ---------------------------------------------------------------------------
// Controls — the legal scriptBytes positions must stay accepted
// ---------------------------------------------------------------------------

test "N-105: accepted scriptBytes positions still compile" {
    const a = std.testing.allocator;
    for ([_][]const u8{
        RAW_BYTESTRING_SCRIPT,
        RAW_STATE_SCRIPT,
        RAW_SUBTYPE_SCRIPT,
        RAW_HELPER_SCRIPT,
        DATA_BYTESTRING_SCRIPT,
    }) |src| {
        const hex = try compileHex(a, src);
        defer a.free(hex);
        try std.testing.expect(hex.len > 0);
    }
}

// Non-vacuity: "it compiled" would also hold for a tier that discarded the
// scriptBytes operand. Two DIFFERENT ByteString operands must lower to
// different scripts.
test "N-105: the scriptBytes operand reaches codegen" {
    const a = std.testing.allocator;
    const x = try compileHex(a, RAW_BYTESTRING_SCRIPT);
    defer a.free(x);
    const y = try compileHex(a, RAW_STATE_SCRIPT);
    defer a.free(y);
    try std.testing.expect(!std.mem.eql(u8, x, y));
}
