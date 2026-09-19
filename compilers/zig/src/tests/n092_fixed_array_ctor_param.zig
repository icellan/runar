//! N-092 — a FixedArray may not be a CONSTRUCTOR PARAMETER.
//!
//! A property's deploy-time value reaches the locking script through a
//! constructor SLOT: the SDK splices `constructorArgs[slot.paramIndex]` into
//! the bytes that slot names. `passes/expand_fixed_arrays.zig` splits a
//! FixedArray PROPERTY into scalar siblings, but a constructor PARAMETER has no
//! such expansion pass, so there is nothing for an argument to be spliced into.
//!
//! Five tiers refuse the shape outright for exactly that reason, with one
//! diagnostic they all share (Go alone respells it in its own lowercase
//! house style):
//!
//!     ts / rust / python / java  "Constructor parameter 'xs' cannot be a
//!                                 FixedArray. Use initialized properties or
//!                                 pass each element as a separate parameter."
//!     go                         same rule, lowercase + em-dash
//!     zig (before)               ACCEPTS
//!     ruby (before)              ACCEPTS
//!
//! This tier did not merely skip a diagnostic. It COMPILED the source, and
//! measured before the fix:
//!
//!     runar-zig compile CtorFA.runar.ts --hex   -> 960 hex chars, exit 0
//!     artifact "constructorSlots": []
//!
//! An empty slot list on a stateful contract whose ONLY state property is the
//! FixedArray means the deployer's argument has nowhere to go: the script is
//! deployable and the state it carries can never be set from the constructor
//! argument the ABI advertises. Ruby emitted the byte-identical script, so the
//! two tiers agreed with each other and with nobody else — the shape this repo
//! has been bitten by before (7-tier agreement proves agreement, not
//! correctness).
//!
//! Note the probe body below asserts on the METHOD PARAMETER, not on
//! `this.xs[0]`. The originally filed probe did the latter, which this tier
//! rejected at TYPECHECK for an unrelated reason ("left operand of '>=' must be
//! bigint, got 'unknown'") — three passes late, with a message that names
//! neither the constructor nor the rule. A fixture rejected for the wrong
//! reason would have made this whole file vacuous.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const compiler_api = @import("../compiler_api.zig");

/// The cross-tier diagnostic, spelled exactly as TS / Rust / Python / Java emit
/// it. Asserting on the MESSAGE rather than on "some error occurred" is the
/// point: the rejection-parity gate compares diagnostics, and a rejection for
/// an unrelated reason would otherwise pass here and stop guarding anything.
const CTOR_FA = "Constructor parameter 'xs' cannot be a FixedArray. " ++
    "Use initialized properties or pass each element as a separate parameter.";

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// The defect: FixedArray constructor parameter on a stateful contract.
const BAD_STATEFUL =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class CtorFA extends StatefulSmartContract {
    \\  xs: FixedArray<bigint, 3>;
    \\  constructor(xs: FixedArray<bigint, 3>) {
    \\    super(xs);
    \\    this.xs = xs;
    \\  }
    \\  public go(i: bigint) {
    \\    assert(i >= 0n);
    \\  }
    \\}
;

/// The same shape on a STATELESS contract. The five tiers gate on the
/// parameter's type alone, not on the parent class, so scoping the port to
/// StatefulSmartContract would reopen half the hole.
const BAD_STATELESS =
    \\import { SmartContract, assert } from 'runar-lang';
    \\class CtorFAStateless extends SmartContract {
    \\  readonly xs: FixedArray<bigint, 3>;
    \\  constructor(xs: FixedArray<bigint, 3>) {
    \\    super(xs);
    \\    this.xs = xs;
    \\  }
    \\  public go(i: bigint) {
    \\    assert(i >= 0n);
    \\  }
    \\}
;

/// Control 1 — the SUPPORTED form. A FixedArray PROPERTY with a literal
/// initializer needs no constructor argument at all, so `expand_fixed_arrays`
/// has something to work with. Must keep compiling, byte-for-byte.
const GOOD_INITIALIZED_PROPERTY =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class CtrlFA extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  xs: FixedArray<bigint, 3> = [1n, 2n, 3n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public go(v: bigint) {
    \\    assert(this.owner > 0n);
    \\    this.xs[0] = v;
    \\  }
    \\}
;

/// Control 2 — a scalar constructor parameter. The new rule must key on the
/// parameter's TYPE, not merely on the presence of a constructor parameter.
const GOOD_SCALAR_CTOR_PARAM =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class CtrlScalar extends StatefulSmartContract {
    \\  owner: bigint;
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public go(i: bigint) {
    \\    assert(i >= this.owner);
    \\  }
    \\}
;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse + validate a `.runar.ts` source and report whether any VALIDATION
/// error contains `needle`. A parse failure is surfaced as an error rather than
/// silently counted as a rejection.
fn validateHasError(a: std.mem.Allocator, src: []const u8, needle: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();

    const parsed = parse_ts.parseTs(w, src, "N092.runar.ts");
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    const contract = parsed.contract orelse return error.TestFixtureDidNotParse;

    const result = try validate.validate(w, contract);
    for (result.errors) |d| {
        if (std.mem.indexOf(u8, d.message, needle) != null) return true;
    }
    return false;
}

/// Compile end-to-end and hand back the locking-script hex (caller frees).
fn compileHex(a: std.mem.Allocator, src: []const u8, file_name: []const u8) ![]const u8 {
    const result = try compiler_api.compileSource(a, src, file_name);
    if (result.artifact_json) |j| a.free(j);
    return result.script_hex;
}

// ---------------------------------------------------------------------------
// The defect
// ---------------------------------------------------------------------------

test "N-092: a FixedArray constructor parameter is a validation error" {
    const a = std.testing.allocator;
    try std.testing.expect(try validateHasError(a, BAD_STATEFUL, CTOR_FA));
}

test "N-092: the rule is not scoped to StatefulSmartContract" {
    const a = std.testing.allocator;
    try std.testing.expect(try validateHasError(a, BAD_STATELESS, CTOR_FA));
}

test "N-092: the whole compile refuses it — no locking script is emitted" {
    const a = std.testing.allocator;
    try std.testing.expectError(
        error.ValidationFailed,
        compiler_api.compileSource(a, BAD_STATEFUL, "CtorFA.runar.ts"),
    );
    try std.testing.expectError(
        error.ValidationFailed,
        compiler_api.compileSource(a, BAD_STATELESS, "CtorFAStateless.runar.ts"),
    );
}

// ---------------------------------------------------------------------------
// Cross-surface: a SEPARATE gap, deliberately not asserted here
// ---------------------------------------------------------------------------
//
// The Solidity surface can express this shape — `constructor(bigint[3] xs)` —
// and Go / Rust / Python parse it and then reject it with this same rule. THIS
// tier's Solidity parser cannot parse an array-typed parameter at all:
//
//     zig:  parse error: expected parameter name after type 'bigint'
//     ruby: line 6: expected token kind 1, got 8 ("[")
//
// So a `.runar.sol` probe is refused here for the wrong reason, and asserting
// on it would be the bare-catch anti-pattern in a new costume. That parser hole
// is a frontend-parity finding of its own (CLAUDE.md invariant 1: all seven
// tiers parse all nine surfaces) and is filed separately rather than papered
// over with a green test.

// ---------------------------------------------------------------------------
// Controls — the supported forms must be byte-unchanged
// ---------------------------------------------------------------------------
//
// Hexes pinned from the pre-fix binary (`runar-zig compile <src> --hex`), so a
// port that over-reaches and starts refusing legal contracts fails here rather
// than at conformance time.

/// Pre-fix hex of GOOD_INITIALIZED_PROPERTY. The Ruby tier emits the same
/// bytes; both were captured before the rule was ported.
const GOOD_INITIALIZED_PROPERTY_HEX = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f8201199d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f75820118947f77587f7c817c587f7c817c810000a069577a537a75567a567a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c5880537a58807e7b58807e5279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777";
/// Pre-fix hex of GOOD_SCALAR_CTOR_PARAM. Ruby agrees byte-for-byte.
const GOOD_SCALAR_CTOR_PARAM_HEX = "76ab76aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad69768254947f7701007e8101419d01687f7782012c947f758258947f758258947f77817c78a277";

fn expectHex(a: std.mem.Allocator, src: []const u8, file_name: []const u8, want: []const u8) !void {
    const hex = try compileHex(a, src, file_name);
    defer a.free(hex);
    try std.testing.expectEqualStrings(want, hex);
}

test "N-092 control: a FixedArray property with an initializer still compiles, byte-identical" {
    const a = std.testing.allocator;
    try expectHex(a, GOOD_INITIALIZED_PROPERTY, "CtrlFA.runar.ts", GOOD_INITIALIZED_PROPERTY_HEX);
}

test "N-092 control: a scalar constructor parameter still compiles, byte-identical" {
    const a = std.testing.allocator;
    try expectHex(a, GOOD_SCALAR_CTOR_PARAM, "CtrlScalar.runar.ts", GOOD_SCALAR_CTOR_PARAM_HEX);
}
