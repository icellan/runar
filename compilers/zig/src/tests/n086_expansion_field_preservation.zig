//! N-086 — `passes/expand_fixed_arrays.zig` rebuilt IR nodes field-by-field and
//! silently reset every field it did not name.
//!
//! Zig's struct literals fill an omitted field from its `= default` and compile
//! clean, so a reconstruction that names five of six fields is indistinguishable
//! from a correct one at the type level. This pass fires ONLY when the contract
//! also declares a `FixedArray<T, N>` property, which is why four separate
//! fields rode the same defect unnoticed.
//!
//! Measured with the tier's own CLI, fold-ON, BEFORE the fix:
//!
//!   MethodNode.sighash_type      @sighash SINGLE|FORKID + FixedArray
//!                                -> byte-IDENTICAL to the default-mode script.
//!                                   Zero difference is the failure mode: the
//!                                   contract commits to ALL|FORKID while the
//!                                   author declared SINGLE|FORKID, and
//!                                   `sighash_validate` has ALREADY accepted
//!                                   the declared mode by the time this pass
//!                                   throws it away — so the soundness analysis
//!                                   was performed against a mode that never
//!                                   reached the emitter.
//!
//!   ConstructorNode.body         a constructor `assert(owner > 5n)` + FixedArray
//!                                -> ANF IR identical to the same contract with
//!                                   NO such assert. Without the FixedArray the
//!                                   two differ (the R-040 statements are live).
//!
//!   ForStmt.inclusive            `for (let i = 0n; i <= 2n; i++)` + FixedArray
//!                                -> byte-identical to `i < 2n` (1445 hex chars
//!                                   both). Without the FixedArray they differ
//!                                   (1405 vs 1391): the inclusive endpoint is a
//!                                   whole extra unrolled iteration, silently
//!                                   dropped.
//!
//!   CallExpr.asm_return_type     `asm<ByteString>(...)` then `a + a`, at two
//!                                sites (`rewriteExpression`, `cloneExpr`)
//!                                -> `...938277529d...` (OP_ADD) with the
//!                                   FixedArray, `...7e8277529d...` (OP_CAT)
//!                                   without. Same chain the Python tier's
//!                                   R-026 arm documented: asm_return_type ->
//!                                   byte-typed expression -> bin_op result
//!                                   type -> OP_CAT selection.
//!
//! Deliberately NOT fixed here: `PropertyNode.embed_always` is dropped by this
//! pass in all SEVEN tiers including the TypeScript reference. Fixing Zig alone
//! would manufacture a 1-vs-6 divergence. Filed as its own seven-tier item.
//! `Assign.index_target` is also omitted, correctly — the pass's contract is
//! that it is null by the time ANF lowering runs.
//!
//! Every test below asserts on emitted bytes or on the ANF, never on "it
//! compiles": broken and fixed both compile.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const types = @import("../ir/types.zig");

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// A stateful contract with a FixedArray property. `@sighash` goes in for
/// `directive`. The method binds exactly one output, because
/// `passes/sighash_validate.zig` rejects a mutate-only SINGLE continuation as a
/// value-skim vector — a mutate-only body would never reach the expansion pass.
fn boardSrc(comptime directive: []const u8) []const u8 {
    return "import { StatefulSmartContract, assert } from 'runar-lang';\n" ++
        "class Boardy extends StatefulSmartContract {\n" ++
        "  readonly owner: bigint;\n" ++
        "  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];\n" ++
        "  constructor(owner: bigint) {\n" ++
        "    super(owner);\n" ++
        "    this.owner = owner;\n" ++
        "  }\n" ++
        "  " ++ directive ++ "\n" ++
        "  public bump(v: bigint): void {\n" ++
        "    assert(this.owner > 0n);\n" ++
        "    this.addOutput(1000n, this.cells[0], this.cells[1], this.cells[2]);\n" ++
        "  }\n" ++
        "}\n";
}

/// The discriminating control: the SAME directive on a contract with NO
/// FixedArray property. `expand()` early-outs, so this path never reaches the
/// rewrite and must carry the declared mode both before and after the fix.
fn plainSrc(comptime directive: []const u8) []const u8 {
    return "import { StatefulSmartContract, assert } from 'runar-lang';\n" ++
        "class Boardy extends StatefulSmartContract {\n" ++
        "  readonly owner: bigint;\n" ++
        "  n: bigint;\n" ++
        "  constructor(owner: bigint, n: bigint) {\n" ++
        "    super(owner, n);\n" ++
        "    this.owner = owner;\n" ++
        "    this.n = n;\n" ++
        "  }\n" ++
        "  " ++ directive ++ "\n" ++
        "  public bump(v: bigint): void {\n" ++
        "    assert(this.owner > 0n);\n" ++
        "    this.addOutput(1000n, this.n);\n" ++
        "  }\n" ++
        "}\n";
}

/// FixedArray contract whose constructor carries a statement that is neither a
/// `super(...)` call nor a property assignment (R-040's `ConstructorNode.body`).
fn ctorSrc(comptime extra: []const u8) []const u8 {
    return "import { StatefulSmartContract, assert } from 'runar-lang';\n" ++
        "class Ctory extends StatefulSmartContract {\n" ++
        "  readonly owner: bigint;\n" ++
        "  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];\n" ++
        "  constructor(owner: bigint) {\n" ++
        "    super(owner);\n" ++
        "    this.owner = owner;\n" ++
        "    " ++ extra ++ "\n" ++
        "  }\n" ++
        "  public bump(v: bigint): void {\n" ++
        "    assert(this.owner > 0n);\n" ++
        "    this.addOutput(1000n, this.cells[0], this.cells[1], this.cells[2]);\n" ++
        "  }\n" ++
        "}\n";
}

/// FixedArray contract with a C-style for loop whose comparison operator is
/// substituted in — `<=` sets `ForStmt.inclusive`, `<` leaves it false.
fn loopSrc(comptime op: []const u8) []const u8 {
    return "import { StatefulSmartContract, assert } from 'runar-lang';\n" ++
        "class Loopy extends StatefulSmartContract {\n" ++
        "  readonly owner: bigint;\n" ++
        "  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];\n" ++
        "  constructor(owner: bigint) {\n" ++
        "    super(owner);\n" ++
        "    this.owner = owner;\n" ++
        "  }\n" ++
        "  public bump(v: bigint): void {\n" ++
        "    assert(this.owner > 0n);\n" ++
        "    let acc: bigint = 0n;\n" ++
        "    for (let i = 0n; i " ++ op ++ " 2n; i++) {\n" ++
        "      acc = acc + v;\n" ++
        "    }\n" ++
        "    assert(acc >= 0n);\n" ++
        "    this.addOutput(1000n, this.cells[0], this.cells[1], this.cells[2]);\n" ++
        "  }\n" ++
        "}\n";
}

/// Same loop, no FixedArray — the control that proves `inclusive` is live.
fn plainLoopSrc(comptime op: []const u8) []const u8 {
    return "import { StatefulSmartContract, assert } from 'runar-lang';\n" ++
        "class Loopy extends StatefulSmartContract {\n" ++
        "  readonly owner: bigint;\n" ++
        "  n: bigint;\n" ++
        "  constructor(owner: bigint, n: bigint) {\n" ++
        "    super(owner, n);\n" ++
        "    this.owner = owner;\n" ++
        "    this.n = n;\n" ++
        "  }\n" ++
        "  public bump(v: bigint): void {\n" ++
        "    assert(this.owner > 0n);\n" ++
        "    let acc: bigint = 0n;\n" ++
        "    for (let i = 0n; i " ++ op ++ " 2n; i++) {\n" ++
        "      acc = acc + v;\n" ++
        "    }\n" ++
        "    assert(acc >= 0n);\n" ++
        "    this.addOutput(1000n, this.n);\n" ++
        "  }\n" ++
        "}\n";
}

/// `asm<ByteString>` expression form. `arrayProp` is either the FixedArray
/// declaration or empty.
fn asmSrc(comptime arrayProp: []const u8) []const u8 {
    return "import { UnsafeSmartContract, assert, len } from 'runar-lang';\n" ++
        "class Asmy extends UnsafeSmartContract {\n" ++
        "  " ++ arrayProp ++ "\n" ++
        "  readonly n: bigint;\n" ++
        "  constructor(n: bigint) { super(n); this.n = n; }\n" ++
        "  public go(): void {\n" ++
        "    const a: ByteString = asm<ByteString>({ body: '00', in_arity: 0, out_arity: 1 });\n" ++
        "    const c: ByteString = a + a;\n" ++
        "    assert(len(c) === 2n);\n" ++
        "    assert(this.n > 0n);\n" ++
        "  }\n" ++
        "}\n";
}

const ARRAY_PROP = "readonly board: FixedArray<bigint, 3> = [1n, 2n, 3n];";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 0x43 — SIGHASH_SINGLE | SIGHASH_FORKID.
const SINGLE_FORKID: i32 = 0x43;

fn hexOf(a: std.mem.Allocator, source: []const u8, file_name: []const u8) ![]const u8 {
    const r = try compiler_api.compileSource(a, source, file_name);
    if (r.artifact_json) |j| a.free(j);
    return r.script_hex;
}

/// Positions (in BYTES, not hex chars) where `mode` differs from `base`. Each
/// difference must be exactly `from` -> `to`; anything else fails loudly rather
/// than being counted, so an unrelated codegen change cannot be absorbed.
fn flagSwapPositions(
    a: std.mem.Allocator,
    base: []const u8,
    mode: []const u8,
    from: []const u8,
    to: []const u8,
) ![]usize {
    try std.testing.expectEqual(base.len, mode.len);
    var out: std.ArrayListUnmanaged(usize) = .empty;
    var i: usize = 0;
    while (i + 1 < base.len) : (i += 2) {
        const b = base[i .. i + 2];
        const m = mode[i .. i + 2];
        if (!std.mem.eql(u8, b, m)) {
            try std.testing.expectEqualStrings(from, b);
            try std.testing.expectEqualStrings(to, m);
            try out.append(a, i / 2);
        }
    }
    return out.toOwnedSlice(a);
}

/// The `sighash_flag` carried by the FIRST `check_preimage` binding in the
/// compiled ANF — the node StackLower reads for the OP_PUSH_TX binding blob and
/// the one every SDK mirrors when it builds the preimage off-chain. Null when
/// the contract has no `check_preimage` at all.
fn anfSighashFlag(work: std.mem.Allocator, source: []const u8, file_name: []const u8) !?i32 {
    var diag: compiler_api.Diagnostics = .{};
    const pipeline = compiler_api.runPipeline(work, source, file_name, .{}, &diag) catch |err| {
        for (diag.errors.items) |line| std.debug.print("{s}\n", .{line});
        return err;
    };
    const program = pipeline.program orelse return error.ANFLowerFailed;
    for (program.methods) |m| {
        for (m.bindings) |b| {
            if (b.value == .check_preimage) return b.value.check_preimage.sighash_flag;
        }
    }
    return null;
}

/// The post-expansion `sighash_type` on the named method, read straight off the
/// contract `runPipeline` hands back (which IS the expanded one).
fn expandedSighashType(
    work: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
    method: []const u8,
) !?i32 {
    var diag: compiler_api.Diagnostics = .{};
    const pipeline = compiler_api.runPipeline(work, source, file_name, .{}, &diag) catch |err| {
        for (diag.errors.items) |line| std.debug.print("{s}\n", .{line});
        return err;
    };
    for (pipeline.contract.methods) |m| {
        if (std.mem.eql(u8, m.name, method)) return m.sighash_type;
    }
    return error.ANFLowerFailed;
}

/// Space-separated ANF binding kinds of the compiled contract's `constructor`.
fn constructorKinds(work: std.mem.Allocator, source: []const u8, file_name: []const u8) ![]const u8 {
    var diag: compiler_api.Diagnostics = .{};
    const pipeline = compiler_api.runPipeline(work, source, file_name, .{
        .disable_constant_folding = true,
    }, &diag) catch |err| {
        for (diag.errors.items) |line| std.debug.print("{s}\n", .{line});
        return err;
    };
    const program = pipeline.program orelse return error.ANFLowerFailed;
    for (program.methods) |m| {
        if (!std.mem.eql(u8, m.name, "constructor")) continue;
        var out: std.ArrayListUnmanaged(u8) = .empty;
        for (m.bindings, 0..) |b, i| {
            if (i > 0) try out.append(work, ' ');
            try out.appendSlice(work, @tagName(b.value));
        }
        return out.items;
    }
    return error.ANFLowerFailed;
}

// ---------------------------------------------------------------------------
// MethodNode.sighash_type
// ---------------------------------------------------------------------------

test "N-086 expansion keeps @sighash on the rewritten method (AST)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const got = try expandedSighashType(
        arena.allocator(),
        boardSrc("/** @sighash SINGLE|FORKID */"),
        "Boardy.runar.ts",
        "bump",
    );
    try std.testing.expectEqual(@as(?i32, SINGLE_FORKID), got);
}

test "N-086 ANF check_preimage carries the declared flag with a FixedArray" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const flag = try anfSighashFlag(
        arena.allocator(),
        boardSrc("/** @sighash SINGLE|FORKID */"),
        "Boardy.runar.ts",
    );
    try std.testing.expectEqual(@as(?i32, SINGLE_FORKID), flag);
}

test "N-086 control: default mode leaves the ANF flag at 0 with a FixedArray" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const flag = try anfSighashFlag(arena.allocator(), boardSrc(""), "Boardy.runar.ts");
    try std.testing.expectEqual(@as(?i32, 0), flag);
}

test "N-086 control: the same directive with NO FixedArray never reaches the rewrite" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const flag = try anfSighashFlag(
        arena.allocator(),
        plainSrc("/** @sighash SINGLE|FORKID */"),
        "Boardy.runar.ts",
    );
    try std.testing.expectEqual(@as(?i32, SINGLE_FORKID), flag);
}

test "N-086 FixedArray SINGLE differs from default at exactly the binding-flag bytes" {
    const a = std.testing.allocator;
    const single = try hexOf(a, boardSrc("/** @sighash SINGLE|FORKID */"), "Boardy.runar.ts");
    defer a.free(single);
    const dflt = try hexOf(a, boardSrc(""), "Boardy.runar.ts");
    defer a.free(dflt);

    const moved = try flagSwapPositions(a, dflt, single, "41", "43");
    defer a.free(moved);

    // Under the drop the two scripts are byte-IDENTICAL, so zero difference is
    // the failure mode. Exactly two flag bytes move: the auto-injected
    // `extractSigHashType(pre) === <mode>` assert push and the OP_PUSH_TX
    // binding blob's appended DER sighash byte.
    try std.testing.expectEqualSlices(usize, &[_]usize{ 388, 516 }, moved);
}

test "N-086 control: no-FixedArray SINGLE moves the same two flag bytes" {
    const a = std.testing.allocator;
    const single = try hexOf(a, plainSrc("/** @sighash SINGLE|FORKID */"), "Boardy.runar.ts");
    defer a.free(single);
    const dflt = try hexOf(a, plainSrc(""), "Boardy.runar.ts");
    defer a.free(dflt);

    const moved = try flagSwapPositions(a, dflt, single, "41", "43");
    defer a.free(moved);
    try std.testing.expectEqual(@as(usize, 2), moved.len);
}

// ---------------------------------------------------------------------------
// ConstructorNode.body  (R-040)
// ---------------------------------------------------------------------------

test "N-086 expansion keeps constructor body statements" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const work = arena.allocator();

    const with_assert = try constructorKinds(work, ctorSrc("assert(owner > 5n);"), "Ctory.runar.ts");
    const plain = try constructorKinds(work, ctorSrc(""), "Ctory.runar.ts");

    // Under the drop these two are EQUAL: the author's constructor assert is
    // silently discarded because the contract also declares a FixedArray.
    try std.testing.expect(!std.mem.eql(u8, with_assert, plain));
    try std.testing.expect(std.mem.indexOf(u8, with_assert, "assert") != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "assert") == null);
}

// ---------------------------------------------------------------------------
// ForStmt.inclusive
// ---------------------------------------------------------------------------

test "N-086 expansion keeps an inclusive loop bound (one extra unrolled iteration)" {
    const a = std.testing.allocator;
    const inclusive = try hexOf(a, loopSrc("<="), "Loopy.runar.ts");
    defer a.free(inclusive);
    const exclusive = try hexOf(a, loopSrc("<"), "Loopy.runar.ts");
    defer a.free(exclusive);

    // Under the drop these are byte-identical (1445 hex chars each): `i <= 2n`
    // silently unrolls two iterations instead of three.
    try std.testing.expect(!std.mem.eql(u8, inclusive, exclusive));
    try std.testing.expect(inclusive.len > exclusive.len);
}

test "N-086 control: the same loop with NO FixedArray already differs" {
    const a = std.testing.allocator;
    const inclusive = try hexOf(a, plainLoopSrc("<="), "Loopy.runar.ts");
    defer a.free(inclusive);
    const exclusive = try hexOf(a, plainLoopSrc("<"), "Loopy.runar.ts");
    defer a.free(exclusive);
    try std.testing.expect(inclusive.len > exclusive.len);
}

// ---------------------------------------------------------------------------
// CallExpr.asm_return_type  (the Zig arm of R-026)
// ---------------------------------------------------------------------------

test "N-086 expansion keeps asm<ByteString> so `+` still lowers to OP_CAT" {
    const a = std.testing.allocator;
    const with_array = try hexOf(a, asmSrc(ARRAY_PROP), "Asmy.runar.ts");
    defer a.free(with_array);
    const without = try hexOf(a, asmSrc(""), "Asmy.runar.ts");
    defer a.free(without);

    // The control pins the correct lowering: OP_CAT (0x7e), not OP_ADD (0x93).
    try std.testing.expectEqualStrings("0076767e8277529d0000a077", without);
    // Under the drop the FixedArray variant reads "007676938277529d0000a077".
    try std.testing.expectEqualStrings(without, with_array);
}
