//! Port of the TypeScript reference test
//! `packages/runar-compiler/src/__tests__/n105-output-shape.test.ts`.
//!
//! N-105 (2/2) — the rest of TypeScript's output-intrinsic CONTRACT: the
//! StatefulSmartContract gate, the arity of all three intrinsics, and the types
//! of addOutput's state values.
//!
//! N-098 ported the satoshis check and N-105 (1/2) the scriptBytes check. These
//! three are the remainder, and each was a hole with an executed consequence:
//!
//!   this.addOutput(1000n)                  1352 hexchars — the state value is
//!     with one mutable property            simply MISSING from the
//!                                          continuation; the correct call
//!                                          emits 1362.
//!   this.addOutput(1000n, this.count, 5n)  1368 hexchars — the surplus value
//!                                          is appended to a state
//!                                          serialization the next spend
//!                                          deserializes by fixed offsets.
//!   this.addOutput(1000n, this.blob)       1362 hexchars, DIFFERENT bytes —
//!     with count: bigint                   the ByteString is serialized where
//!                                          an 8-byte LE number belongs.
//!   this.addRawOutput(...) in a            152 hexchars — a "continuation" in
//!     stateless SmartContract              a contract that has no state.
//!
//! All four are the same class as N-098: the compiler does not refuse, it emits
//! a covenant that commits to the wrong thing.
//!
//! Ported from the TypeScript reference, wording included. This tier previously
//! answered the gate with its own wording ("... is only available in
//! StatefulSmartContract, not SmartContract"); it now answers with the
//! reference's, and the gate now covers all three intrinsics rather than
//! reporting and continuing.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");
const compiler_api = @import("../compiler_api.zig");

const HEAD =
    \\import { StatefulSmartContract, ByteString, PubKey, assert } from 'runar-lang';
    \\class C extends StatefulSmartContract {
    \\  count: bigint;
    \\  owner: PubKey;
    \\  readonly base: bigint;
    \\  readonly blob: ByteString;
    \\  constructor(count: bigint, owner: PubKey, base: bigint, blob: ByteString) {
    \\    super(count, owner, base, blob);
    \\    this.count = count;
    \\    this.owner = owner;
    \\    this.base = base;
    \\    this.blob = blob;
    \\  }
    \\  private anything(): bigint { return this.base; }
    \\
;

const STATELESS_HEAD =
    \\import { SmartContract, ByteString, assert } from 'runar-lang';
    \\class C extends SmartContract {
    \\  readonly base: bigint;
    \\  readonly blob: ByteString;
    \\  constructor(base: bigint, blob: ByteString) {
    \\    super(base, blob);
    \\    this.base = base;
    \\    this.blob = blob;
    \\  }
    \\
;

// --- REJECT: arity ---------------------------------------------------------

const ARITY_TOO_FEW = HEAD ++
    \\  public m(n: bigint, who: PubKey) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.owner = who;
    \\    this.addOutput(1000n, this.count);
    \\  }
    \\}
;

const ARITY_TOO_MANY = HEAD ++
    \\  public m(n: bigint, who: PubKey) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.owner = who;
    \\    this.addOutput(1000n, this.count, this.owner, 5n);
    \\  }
    \\}
;

const RAW_ARITY_ONE = HEAD ++
    \\  public m(n: bigint, who: PubKey) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.owner = who;
    \\    this.addOutput(1000n, this.count, this.owner);
    \\    this.addRawOutput(500n);
    \\  }
    \\}
;

const RAW_ARITY_THREE = HEAD ++
    \\  public m(n: bigint, who: PubKey) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.owner = who;
    \\    this.addOutput(1000n, this.count, this.owner);
    \\    this.addRawOutput(500n, this.blob, 7n);
    \\  }
    \\}
;

const DATA_ARITY_THREE = HEAD ++
    \\  public m(n: bigint, who: PubKey) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.owner = who;
    \\    this.addOutput(1000n, this.count, this.owner);
    \\    this.addDataOutput(500n, this.blob, 7n);
    \\  }
    \\}
;

// --- REJECT: state-value types ---------------------------------------------

const STATE_VALUE_WRONG_TYPE = HEAD ++
    \\  public m(n: bigint, who: PubKey) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.owner = who;
    \\    this.addOutput(1000n, this.blob, this.owner);
    \\  }
    \\}
;

// --- REJECT: the StatefulSmartContract gate --------------------------------

const STATELESS_ADD_OUTPUT = STATELESS_HEAD ++
    \\  public m(n: bigint) {
    \\    this.addOutput(1000n, n);
    \\    assert(n > 0n);
    \\  }
    \\}
;

const STATELESS_ADD_RAW_OUTPUT = STATELESS_HEAD ++
    \\  public m(n: bigint) {
    \\    this.addRawOutput(1000n, this.blob);
    \\    assert(n > 0n);
    \\  }
    \\}
;

const STATELESS_ADD_DATA_OUTPUT = STATELESS_HEAD ++
    \\  public m(n: bigint) {
    \\    this.addDataOutput(1000n, this.blob);
    \\    assert(n > 0n);
    \\  }
    \\}
;

// --- ACCEPT (over-rejection guards) ----------------------------------------

const SHAPE_EXACT = HEAD ++
    \\  public m(n: bigint, who: PubKey) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.owner = who;
    \\    this.addOutput(1000n, this.count, this.owner);
    \\  }
    \\}
;

/// A ByteString value in a PubKey state slot. TS's isSubtype treats the
/// ByteString family as bidirectionally compatible, so TS ACCEPTS this and
/// every tier must keep accepting it — measured before this change, all seven
/// tiers compiled it to the same script.
const SHAPE_FAMILY_WIDENING = HEAD ++
    \\  public m(n: bigint, b: ByteString) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count, b);
    \\  }
    \\}
;

/// A private helper's declared return type is discarded at parse time in every
/// tier, so this infers as unknown. TS escapes it; every port must too.
const SHAPE_UNKNOWN_STATE_VALUE = HEAD ++
    \\  public m(n: bigint, who: PubKey) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.owner = who;
    \\    this.addOutput(1000n, this.anything(), this.owner);
    \\  }
    \\}
;

/// The one-mutable-property shape: the arity rule must be derived from the
/// contract, not hardcoded.
const ONE_PROP =
    \\import { StatefulSmartContract, ByteString, assert } from 'runar-lang';
    \\class C extends StatefulSmartContract {
    \\  count: bigint;
    \\  readonly blob: ByteString;
    \\  constructor(count: bigint, blob: ByteString) {
    \\    super(count, blob);
    \\    this.count = count;
    \\    this.blob = blob;
    \\  }
    \\  public m(n: bigint) {
    \\    assert(n > 0n);
    \\    this.count = this.count + n;
    \\    this.addOutput(1000n, this.count);
    \\    this.addRawOutput(500n, this.blob);
    \\  }
    \\}
;

/// A FixedArray state property. expand_fixed_arrays runs AFTER the typechecker
/// in this tier and splits `board` into three scalar siblings, so the only call
/// shape that lowers is the EXPANDED one below — which the arity rule, counting
/// the two DECLARED mutable properties, would reject. This is the contract from
/// compilers/python/tests/test_r025_expand_fixed_arrays_field_preservation.py,
/// checked into this repo and compiled by all six non-TS tiers; the TypeScript
/// reference rejects it ("expects 3 argument(s) ... got 5"), which is a defect
/// in the reference rule, not in this source.
const FIXED_ARRAY_STATE =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { FixedArray } from 'runar-lang';
    \\class Boardy extends StatefulSmartContract {
    \\  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  n: bigint;
    \\  constructor(n: bigint) { super(n); this.n = n; }
    \\  public bump(): void { this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n); }
    \\}
;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

test "N-105: addOutput arity" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        ARITY_TOO_FEW,
        "addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 2",
    ));
    try std.testing.expect(try typecheckHasError(
        a,
        ARITY_TOO_MANY,
        "addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 4",
    ));
}

test "N-105: addRawOutput / addDataOutput arity" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        RAW_ARITY_ONE,
        "addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 1",
    ));
    try std.testing.expect(try typecheckHasError(
        a,
        RAW_ARITY_THREE,
        "addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 3",
    ));
    try std.testing.expect(try typecheckHasError(
        a,
        DATA_ARITY_THREE,
        "addDataOutput() expects 2 arguments (satoshis, scriptBytes), got 3",
    ));
}

test "N-105: addOutput state-value types" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        STATE_VALUE_WRONG_TYPE,
        "addOutput() argument 2 (count) must be 'bigint', got 'ByteString'",
    ));
}

test "N-105: the output intrinsics are StatefulSmartContract-only" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        STATELESS_ADD_OUTPUT,
        "addOutput() is only available in StatefulSmartContract",
    ));
    try std.testing.expect(try typecheckHasError(
        a,
        STATELESS_ADD_RAW_OUTPUT,
        "addRawOutput() is only available in StatefulSmartContract",
    ));
    try std.testing.expect(try typecheckHasError(
        a,
        STATELESS_ADD_DATA_OUTPUT,
        "addDataOutput() is only available in StatefulSmartContract",
    ));
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

test "N-105: accepted output shapes still compile" {
    const a = std.testing.allocator;
    for ([_][]const u8{
        SHAPE_EXACT,
        SHAPE_FAMILY_WIDENING,
        SHAPE_UNKNOWN_STATE_VALUE,
    }) |src| {
        const hex = try compileHex(a, src);
        defer a.free(hex);
        try std.testing.expect(hex.len > 0);
    }
}

// Non-vacuity: the arity rule must be derived from the contract's mutable
// properties, not hardcoded.
test "N-105: arity is derived from the mutable properties" {
    const a = std.testing.allocator;
    const one = try compileHex(a, ONE_PROP);
    defer a.free(one);
    try std.testing.expect(one.len > 0);
    const two = try compileHex(a, SHAPE_EXACT);
    defer a.free(two);
    try std.testing.expect(two.len > 0);
}

// The carve-out, pinned: a FixedArray-state contract must stay compilable.
test "N-105: FixedArray state is out of scope for the shape checks" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, FIXED_ARRAY_STATE);
    defer a.free(hex);
    try std.testing.expect(hex.len > 0);
}
