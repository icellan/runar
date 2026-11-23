//! A conditional that declares outputs and does ANYTHING ELSE the parent scope
//! can still observe is an unsupported shape and must be a HARD COMPILE ERROR.
//! Port of the TypeScript reference test
//! packages/runar-compiler/src/__tests__/branch-outputs-merged-locals.test.ts.
//!
//! An `if` expression carries exactly ONE value. When a branch contains an
//! output intrinsic that value is already spoken for — it is the output concat
//! the continuation hash consumes (appendBranchOutputConcat). Anything else the
//! arm leaves behind breaks one of two invariants nothing downstream enforces:
//!
//!   INV-A  the parent registers the if-expression's value as the branch's
//!          contribution to the continuation hash, so "the branch's output
//!          bytes" really means "whatever the arm's LAST binding is".
//!   INV-B  an arm that emits an output AND leaves any other nameable slot — a
//!          second merged local, a property write, a rebound local still read
//!          after the `if` — leaves 2+ results against ONE registered stack-map
//!          name.
//!
//! Before the 2026-08-05 fixes the compiler emitted anyway, so the locking
//! script was permanently unspendable (OP_NUM2BIN / OP_NUMEQUALVERIFY / OP_ADD
//! landing on the wrong slot) — or, quieter, the continuation committed a bare
//! script number where a serialized output belonged and the off-chain
//! interpreter agreed with it.
//!
//! The Zig tier raises a typed error, `LowerError.UnrepresentableBranchOutputs`,
//! and hands the actionable detail back through the optional
//! `anf_lower.LowerDiagnostic` sink. `compiler_api.compileSource` propagates the
//! typed error verbatim instead of flattening it to `error.ANFLowerFailed`, so
//! both levels are pinned below.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const compiler_api = @import("../compiler_api.zig");
const types = @import("../ir/types.zig");

// ============================================================================
// Sources (TypeScript surface). Kept byte-identical across all seven tiers.
// ============================================================================

/// REJECTED: `if` with an output intrinsic in each arm, and two locals (`na`,
/// `nb`) merged ASYMMETRICALLY across the branch — the then-arm reassigns `na`,
/// the else-arm reassigns `nb`.
const OUTPUTS_AND_MERGED_LOCALS =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class OutputsAndMergedLocals extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  a: bigint = 0n;
    \\  b: bigint = 0n;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.closed = seed;
    \\  }
    \\
    \\  public bid(bidAmount: bigint): void {
    \\    assert(this.closed === 0n);
    \\    let na = this.a;
    \\    let nb = this.b;
    \\    if (this.a === 0n) {
    \\      na = bidAmount;
    \\      this.addOutput(bidAmount, this.closed, na, nb);
    \\    } else {
    \\      nb = bidAmount;
    \\      this.addOutput(bidAmount, this.closed, na, nb);
    \\    }
    \\  }
    \\}
;

/// REJECTED (INV-A): each arm emits its output and THEN rebinds a local, so the
/// arm's terminal binding — the one the parent registers as the branch's output
/// bytes — is a bare script number, and the real serialized output is dropped by
/// the residue drain.
const OUTPUTS_THEN_REBIND =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class OutputsThenRebind extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  a: bigint = 0n;
    \\  b: bigint = 0n;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.closed = seed;
    \\  }
    \\
    \\  public bid(bidAmount: bigint): void {
    \\    assert(this.closed === 0n);
    \\    let na = this.a;
    \\    if (this.a === 0n) {
    \\      this.addOutput(bidAmount, this.closed, bidAmount, this.b);
    \\      na = bidAmount;
    \\    } else {
    \\      this.addOutput(bidAmount, this.closed, this.a, this.b);
    \\      na = this.a;
    \\    }
    \\    assert(na > 0n);
    \\  }
    \\}
;

/// REJECTED (INV-A, local DEAD after the `if`): identical to the above minus the
/// post-`if` read. Pins that INV-A is independent of liveness, which is why the
/// predicate cannot be liveness-only.
const OUTPUTS_THEN_REBIND_DEAD =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class OutputsThenRebindDead extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  a: bigint = 0n;
    \\  b: bigint = 0n;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.closed = seed;
    \\  }
    \\
    \\  public bid(bidAmount: bigint): void {
    \\    assert(this.closed === 0n);
    \\    let na = this.a;
    \\    if (this.a === 0n) {
    \\      this.addOutput(bidAmount, this.closed, bidAmount, this.b);
    \\      na = bidAmount;
    \\    } else {
    \\      this.addOutput(bidAmount, this.closed, this.a, this.b);
    \\      na = this.a;
    \\    }
    \\  }
    \\}
;

/// REJECTED (INV-A, ZERO merged locals): each arm emits a data output and THEN
/// writes a property, so the receipt bytes are no longer on top and the drain
/// deletes them.
const OUTPUTS_THEN_PROP_WRITE =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { ByteString } from 'runar-lang';
    \\
    \\class OutputsThenPropWrite extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  a: bigint = 0n;
    \\  b: bigint = 0n;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.closed = seed;
    \\  }
    \\
    \\  public pay(payload: ByteString): void {
    \\    assert(this.closed === 0n);
    \\    if (this.a === 0n) {
    \\      this.addDataOutput(0n, payload);
    \\      this.b = 1n;
    \\    } else {
    \\      this.addDataOutput(0n, payload);
    \\      this.b = 2n;
    \\    }
    \\    this.a = this.a + 1n;
    \\  }
    \\}
;

/// REJECTED (INV-B, ZERO merged locals): the property write comes BEFORE the
/// output, so each arm DOES end with its output intrinsic and the ANF-shape
/// invariant holds — and it is still unrepresentable. This is the case that
/// rules out "arm ends with its output" as a sufficient predicate.
const PROP_WRITE_THEN_OUTPUTS =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\import type { ByteString } from 'runar-lang';
    \\
    \\class PropWriteThenOutputs extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  a: bigint = 0n;
    \\  b: bigint = 0n;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.closed = seed;
    \\  }
    \\
    \\  public pay(payload: ByteString): void {
    \\    assert(this.closed === 0n);
    \\    if (this.a === 0n) {
    \\      this.b = 1n;
    \\      this.addDataOutput(0n, payload);
    \\    } else {
    \\      this.b = 2n;
    \\      this.addDataOutput(0n, payload);
    \\    }
    \\    this.a = this.a + 1n;
    \\  }
    \\}
;

/// REJECTED (INV-B, K=1): each arm rebinds one local BEFORE its output, and the
/// local is READ after the `if`, so add_output picks instead of rolling it and
/// the arm ends two deep against one registered stack-map name.
const OUTPUTS_WITH_LIVE_REBIND =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class OutputsWithLiveRebind extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  a: bigint = 0n;
    \\  b: bigint = 0n;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.closed = seed;
    \\  }
    \\
    \\  public bid(bidAmount: bigint): void {
    \\    assert(this.closed === 0n);
    \\    let na = this.a;
    \\    if (this.a === 0n) {
    \\      na = bidAmount;
    \\      this.addOutput(bidAmount, this.closed, na, this.b);
    \\    } else {
    \\      na = bidAmount + 1n;
    \\      this.addOutput(bidAmount, this.closed, na, this.b);
    \\    }
    \\    assert(na === bidAmount);
    \\  }
    \\}
;

/// ACCEPTED control: the same two asymmetrically merged locals, with the
/// addOutput moved after the `if` — the documented workaround, and the shape the
/// guard must NOT fire on.
const OUTPUTS_AFTER_MERGED_LOCALS =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class OutputsAfterMergedLocals extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  a: bigint = 0n;
    \\  b: bigint = 0n;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.closed = seed;
    \\  }
    \\
    \\  public bid(bidAmount: bigint): void {
    \\    assert(this.closed === 0n);
    \\    let na = this.a;
    \\    let nb = this.b;
    \\    if (this.a === 0n) {
    \\      na = bidAmount;
    \\    } else {
    \\      nb = bidAmount;
    \\    }
    \\    this.addOutput(bidAmount, this.closed, na, nb);
    \\  }
    \\}
;

/// ACCEPTED control: the live-rebind shape with the local DEAD after the `if`,
/// so add_output consumes the arm's own copy on last use and the arm leaves
/// exactly one result.
const OUTPUTS_WITH_DEAD_REBIND =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class OutputsWithDeadRebind extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  a: bigint = 0n;
    \\  b: bigint = 0n;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.closed = seed;
    \\  }
    \\
    \\  public bid(bidAmount: bigint): void {
    \\    assert(this.closed === 0n);
    \\    let na = this.a;
    \\    if (this.a === 0n) {
    \\      na = bidAmount;
    \\      this.addOutput(bidAmount, this.closed, na, this.b);
    \\    } else {
    \\      na = bidAmount + 1n;
    \\      this.addOutput(bidAmount, this.closed, na, this.b);
    \\    }
    \\  }
    \\}
;

/// ACCEPTED control / baseline: each arm emits its output and touches nothing
/// else. If this ever stops compiling the predicate has been written far too
/// wide.
const OUTPUTS_ONLY =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class OutputsOnly extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  a: bigint = 0n;
    \\  b: bigint = 0n;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.closed = seed;
    \\  }
    \\
    \\  public bid(bidAmount: bigint): void {
    \\    assert(this.closed === 0n);
    \\    if (this.a === 0n) {
    \\      this.addOutput(bidAmount, this.closed, bidAmount, this.b);
    \\    } else {
    \\      this.addOutput(bidAmount, this.closed, this.a, this.b);
    \\    }
    \\  }
    \\}
;

/// ACCEPTED control: a pre-`if` local IS live across the `if`, but it is not one
/// the arms bind.
const OUTPUTS_WITH_UNRELATED_LIVE_LOCAL =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\
    \\class OutputsWithUnrelatedLiveLocal extends StatefulSmartContract {
    \\  closed: bigint = 0n;
    \\  a: bigint = 0n;
    \\  b: bigint = 0n;
    \\
    \\  constructor(seed: bigint) {
    \\    super(seed);
    \\    this.closed = seed;
    \\  }
    \\
    \\  public bid(bidAmount: bigint): void {
    \\    assert(this.closed === 0n);
    \\    let guard = this.closed;
    \\    let na = this.a;
    \\    if (this.a === 0n) {
    \\      na = bidAmount;
    \\      this.addOutput(bidAmount, this.closed, na, this.b);
    \\    } else {
    \\      na = bidAmount + 1n;
    \\      this.addOutput(bidAmount, this.closed, na, this.b);
    \\    }
    \\    assert(guard === 0n);
    \\  }
    \\}
;

const RejectedCase = struct {
    source: []const u8,
    file_name: []const u8,
    /// The reason clause the diagnostic must name.
    reason: []const u8,
};

const REJECTED_CASES = [_]RejectedCase{
    .{
        .source = OUTPUTS_AND_MERGED_LOCALS,
        .file_name = "OutputsAndMergedLocals.runar.ts",
        .reason = "merges 2 local variables (na, nb)",
    },
    .{
        .source = OUTPUTS_THEN_REBIND,
        .file_name = "OutputsThenRebind.runar.ts",
        .reason = "continues past its output in the then-branch",
    },
    .{
        .source = OUTPUTS_THEN_REBIND_DEAD,
        .file_name = "OutputsThenRebindDead.runar.ts",
        .reason = "continues past its output in the then-branch",
    },
    .{
        .source = OUTPUTS_THEN_PROP_WRITE,
        .file_name = "OutputsThenPropWrite.runar.ts",
        .reason = "continues past its output in the then-branch",
    },
    .{
        .source = PROP_WRITE_THEN_OUTPUTS,
        .file_name = "PropWriteThenOutputs.runar.ts",
        .reason = "assigns contract properties (b) inside the branch",
    },
    .{
        .source = OUTPUTS_WITH_LIVE_REBIND,
        .file_name = "OutputsWithLiveRebind.runar.ts",
        .reason = "reassigns local variables read after it (na)",
    },
};

const AcceptedCase = struct { source: []const u8, file_name: []const u8 };

const ACCEPTED_CASES = [_]AcceptedCase{
    .{ .source = OUTPUTS_AFTER_MERGED_LOCALS, .file_name = "OutputsAfterMergedLocals.runar.ts" },
    .{ .source = OUTPUTS_WITH_DEAD_REBIND, .file_name = "OutputsWithDeadRebind.runar.ts" },
    .{ .source = OUTPUTS_ONLY, .file_name = "OutputsOnly.runar.ts" },
    .{ .source = OUTPUTS_WITH_UNRELATED_LIVE_LOCAL, .file_name = "OutputsWithUnrelatedLiveLocal.runar.ts" },
};

/// Parse + validate + typecheck, returning the contract ready for pass 4.
fn frontend(alloc: std.mem.Allocator, source: []const u8, file_name: []const u8) !types.ContractNode {
    const parsed = parse_ts.parseTs(alloc, source, file_name);
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.TestUnexpectedResult;

    const val_result = try validate.validate(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);

    const tc_result = try typecheck.typeCheck(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    return tc_result.contract;
}

test "conditional that declares outputs and leaves an extra result is rejected by ANF lowering" {
    for (REJECTED_CASES) |tc| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const contract = try frontend(alloc, tc.source, tc.file_name);

        var diag: anf_lower.LowerDiagnostic = .{};
        const result = anf_lower.lowerToANFWithDiagnostic(alloc, contract, &diag);
        try std.testing.expectError(anf_lower.LowerError.UnrepresentableBranchOutputs, result);

        // The sink carries the actionable message, byte-identical in wording to
        // the other six tiers.
        const message = diag.message orelse return error.TestExpectedDiagnostic;
        try std.testing.expect(std.mem.indexOf(
            u8,
            message,
            "Cannot compile conditional that both declares outputs and",
        ) != null);
        try std.testing.expect(std.mem.indexOf(u8, message, tc.reason) != null);
        // Only the workaround that actually works is advertised. The rejected
        // sources already give each branch its own complete addOutput, so the
        // old "or give each branch its own complete addOutput" advice was a
        // dead end.
        try std.testing.expect(std.mem.indexOf(
            u8,
            message,
            "Move the addOutput/addRawOutput/addDataOutput call after the if-statement",
        ) != null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            message,
            "give each branch its own complete addOutput",
        ) == null);
    }
}

test "lowerToANF without a diagnostic sink still refuses the construct" {
    for (REJECTED_CASES) |tc| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const contract = try frontend(alloc, tc.source, tc.file_name);
        try std.testing.expectError(
            anf_lower.LowerError.UnrepresentableBranchOutputs,
            anf_lower.lowerToANF(alloc, contract),
        );
    }
}

test "conditional that declares outputs and leaves an extra result fails the full pipeline" {
    // Expected refusal: keep its diagnostic off stderr (see build.zig).
    std.testing.log_level = .err;
    defer std.testing.log_level = .warn;
    for (REJECTED_CASES) |tc| {
        const result = compiler_api.compileSource(std.testing.allocator, tc.source, tc.file_name);
        // compileSource propagates the pass-4 error verbatim — it must NOT
        // flatten the refusal into the anonymous error.ANFLowerFailed.
        try std.testing.expectError(error.UnrepresentableBranchOutputs, result);
    }
}

test "the accepted branch-output shapes still compile" {
    for (ACCEPTED_CASES) |tc| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const contract = try frontend(alloc, tc.source, tc.file_name);
        const program = try anf_lower.lowerToANF(alloc, contract);
        try std.testing.expect(program.methods.len >= 1);

        const compiled = try compiler_api.compileSource(std.testing.allocator, tc.source, tc.file_name);
        defer compiled.deinit(std.testing.allocator);
        try std.testing.expect(compiled.script_hex.len > 0);
    }
}
