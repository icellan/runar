//! N-124 — port the N-019 `this.arr[i]++` desugar to the Zig tier.
//!
//! `4c062371` fixed a fund-loss defect in five tiers (Rust was already fixed by
//! `5d362da7`): a stateful method whose only mutation was `this.arr[i]++`
//! emitted NO state-continuation covenant — no `update_prop`, no
//! `get_state_script`, no output binding — leaving the spending path
//! unconstrained. Pass 3b desugared only the increment's OPERAND into a read
//! dispatch, so the increment lowering and the mutates-state summary both saw a
//! ternary and dropped the write.
//!
//! Zig was left out of that commit deliberately and was never vulnerable: its
//! typechecker refused `this.arr[i]++` outright (`++ operator requires bigint,
//! got 'unknown'`), because `inferExprType`'s `.index_access` arm returns
//! `.unknown`. A loud refusal, not a silent miscompile — but it also meant Zig
//! could not compile a construct the other six compile correctly, and R-094's
//! testable assertion is exactly "a fixture exercising `this.arr[i]++` must
//! produce byte-identical hex across all seven tiers".
//!
//! The tripwire in `passes/typecheck.zig` named the prerequisite: port the
//! pass-3b desugar BEFORE relaxing the type rule. Both halves land together:
//!
//!   - `expand_fixed_arrays.zig` desugars a STATEMENT-position increment into
//!     `this.arr[idx] = this.arr[idx] ± 1` through the existing
//!     `rewriteIndexAssign` path, with an impure index hoisted once so the read
//!     and the write cannot pick different slots.
//!   - the same pass REFUSES an expression-position increment, which cannot be
//!     desugared and whose write would otherwise be dropped.
//!   - `typecheck.zig`'s `.increment` / `.decrement` arms route through
//!     `inferOperandType` (the R-073 / N-097 shape) instead of `inferExprType`.
//!
//! The bytes below are the GO tier's, captured before any Zig change.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");
const compiler_api = @import("../compiler_api.zig");

/// Runtime-index increment — the N-019 shape verbatim.
const RUNTIME_INCR =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class BumpDyn extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  xs: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(i: bigint) {
    \\    this.xs[i]++;
    \\  }
    \\}
;

/// The same contract with the increment written out by hand. The other six
/// tiers emit byte-identical script for the two; so must this one, because the
/// desugar is literally this rewrite.
const RUNTIME_INCR_BY_HAND =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class BumpDyn extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  xs: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(i: bigint) {
    \\    this.xs[i] = this.xs[i] + 1n;
    \\  }
    \\}
;

/// Literal-index increment. Was the "residual gap" pinned by N-097.
const LITERAL_INCR =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class BumpLit extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  xs: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(v: bigint) {
    \\    this.xs[0]++;
    \\  }
    \\}
;

/// EXPRESSION position. Cannot be desugared: the increment lowering has no way
/// to write back through a read-dispatch chain, so the write would be dropped.
/// Must be refused, in this tier as in the other six.
const EXPRESSION_INCR =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class BumpExpr extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  xs: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(i: bigint) {
    \\    const y: bigint = this.xs[i]++;
    \\    assert(y >= 0n);
    \\  }
    \\}
;

/// Control: the same contract with NO mutation at all. Its script must differ
/// from the increment's — that difference IS the state-continuation covenant,
/// and its absence was the N-019 fund loss.
const NO_MUTATION =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class BumpNone extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  xs: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public probe(i: bigint) {
    \\    assert(this.xs[0] >= 0n);
    \\  }
    \\}
;

const GO_RUNTIME_INCR_HEX =
    \\61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f8201199d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f75820118947f77587f7c817c587f7c817c81577991635279675779519c6378677668688b5879915979519c5a7a529c5279917653799a5379917b7c9a52799a5479547a9b537a9b695679537a635379677668577a755679547a635479677668577a755679557a635579677668577a755a7a5a7a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b757768557a5880547a58807e7b58807e5679587a7c7558806b5779016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa557a820128947f7701207f75877777777777
;

const GO_LITERAL_INCR_HEX =
    \\61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f8201199d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f75820118947f77587f7c817c587f7c817c8152798b537a75567a567a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c5880537a58807e7b58807e5279547a7c7558806b5479016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f75877777
;

fn typecheckErrorCount(a: std.mem.Allocator, src: []const u8) !usize {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = parse_ts.parseTs(w, src, "N124.runar.ts");
    if (parsed.contract == null) return error.TestFixtureDidNotParse;
    const result = try typecheck.typeCheck(w, parsed.contract.?);
    return result.errors.len;
}

fn compileHex(a: std.mem.Allocator, src: []const u8, file_name: []const u8) ![]const u8 {
    const result = try compiler_api.compileSource(a, src, file_name);
    if (result.artifact_json) |j| a.free(j);
    return result.script_hex;
}

test "N-124: a runtime-index increment typechecks" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), try typecheckErrorCount(a, RUNTIME_INCR));
}

test "N-124: a literal-index increment typechecks" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), try typecheckErrorCount(a, LITERAL_INCR));
}

test "N-124: the runtime-index increment is byte-identical to the Go tier" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, RUNTIME_INCR, "BumpDyn.runar.ts");
    defer a.free(hex);
    try std.testing.expectEqualStrings(GO_RUNTIME_INCR_HEX, hex);
}

test "N-124: the literal-index increment is byte-identical to the Go tier" {
    const a = std.testing.allocator;
    const hex = try compileHex(a, LITERAL_INCR, "BumpLit.runar.ts");
    defer a.free(hex);
    try std.testing.expectEqualStrings(GO_LITERAL_INCR_HEX, hex);
}

test "N-124: `arr[i]++` and `arr[i] = arr[i] + 1n` emit the same script" {
    // The desugar IS this rewrite, so any divergence means the increment took
    // a different path than the assignment it is defined to be.
    const a = std.testing.allocator;
    const incr = try compileHex(a, RUNTIME_INCR, "BumpDyn.runar.ts");
    defer a.free(incr);
    const hand = try compileHex(a, RUNTIME_INCR_BY_HAND, "BumpDyn.runar.ts");
    defer a.free(hand);
    try std.testing.expectEqualStrings(hand, incr);
}

test "N-124: the increment carries a state continuation the no-op control does not" {
    // N-019's harm was a mutating method compiled as terminal: no continuation
    // covenant at all. A script equal to the no-mutation control would be that
    // defect. Compared by LENGTH as well, so an accidental equality of two
    // wrong scripts cannot pass.
    const a = std.testing.allocator;
    const incr = try compileHex(a, RUNTIME_INCR, "BumpDyn.runar.ts");
    defer a.free(incr);
    const none = try compileHex(a, NO_MUTATION, "BumpNone.runar.ts");
    defer a.free(none);
    try std.testing.expect(!std.mem.eql(u8, incr, none));
    try std.testing.expect(incr.len > none.len);
}

test "N-124: an EXPRESSION-position increment is refused" {
    const a = std.testing.allocator;
    try std.testing.expectError(
        error.ValidationFailed,
        compiler_api.compileSource(a, EXPRESSION_INCR, "BumpExpr.runar.ts"),
    );
}
