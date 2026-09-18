//! R-021 (CL-BUG-155): the continuation-shape walkers must descend into
//! variable-declaration initialisers.
//!
//! `stmtMutatesStateRec` and `stmtHasIntrinsicCallRec` in
//! `passes/anf_lower.zig` handled only `.expr_stmt` / `.if_stmt` / `.for_stmt`
//! / `.return_stmt`. A `.const_decl` / `.let_decl` was invisible, so a side
//! effect reachable only through a variable-declaration initialiser never
//! reached the `needs_change_output` / `needs_new_amount` / terminal decision.
//!
//! The four tiers that ship a dedicated `side_effect_summary` module (TS, Go,
//! Rust, Python) walk the initialiser, so this is a cross-tier divergence, and
//! it is unsafe in both of its shapes:
//!
//!   1. Output intrinsic behind the initialiser — the private helper IS
//!      ANF-inlined (`shouldInlinePrivate` asks the HELPER, which does see its
//!      own `addOutput`), so the body emits the add_output node and loads
//!      `_changePKH`, but the method header never declared it. Stack lowering
//!      then refuses with SilentOpZeroRefused: a hard failure on valid Rúnar
//!      that four other tiers accept.
//!
//!   2. State mutation behind the initialiser — mutation-only helpers are NOT
//!      inlined, so nothing trips. The method is silently classified TERMINAL:
//!      no continuation params, no state continuation, no covenant. The
//!      deployed script binds NOTHING about where the value goes and a spender
//!      can take the whole UTXO anywhere. Silent, and a funds bug.
//!
//! The expected parameter lists below are the TypeScript reference compiler's
//! own ABI for the same sources.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// Shape 1: `this.addOutput` reachable only via a var-decl initialiser.
const vardecl_output =
    \\class VarDeclOutput extends StatefulSmartContract {
    \\  a: bigint;
    \\
    \\  constructor(a: bigint) {
    \\    super(a);
    \\    this.a = a;
    \\  }
    \\
    \\  private emitAndReturn(amount: bigint): bigint {
    \\    this.addOutput(1000n, this.a);
    \\    return amount;
    \\  }
    \\
    \\  public settle(amount: bigint) {
    \\    const paid: bigint = this.emitAndReturn(amount);
    \\    assert(paid > 0n);
    \\  }
    \\}
;

/// Shape 2: a state mutation reachable only via a var-decl initialiser.
const vardecl_mutation =
    \\class VarDeclMutation extends StatefulSmartContract {
    \\  a: bigint;
    \\
    \\  constructor(a: bigint) {
    \\    super(a);
    \\    this.a = a;
    \\  }
    \\
    \\  private bump(x: bigint): bigint {
    \\    this.a = this.a + 1n;
    \\    return x;
    \\  }
    \\
    \\  public settle(amount: bigint) {
    \\    const paid: bigint = this.bump(amount);
    \\    assert(paid > 0n);
    \\  }
    \\}
;

/// Control: the same effect reached from a bare expression statement.
const stmt_output =
    \\class StmtOutput extends StatefulSmartContract {
    \\  a: bigint;
    \\
    \\  constructor(a: bigint) {
    \\    super(a);
    \\    this.a = a;
    \\  }
    \\
    \\  private emitAndReturn(amount: bigint): bigint {
    \\    this.addOutput(1000n, this.a);
    \\    return amount;
    \\  }
    \\
    \\  public settle(amount: bigint) {
    \\    this.emitAndReturn(amount);
    \\    assert(amount > 0n);
    \\  }
    \\}
;

const settle_with_change =
    "\"name\":\"settle\",\"params\":[" ++
    "{\"name\":\"amount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_changePKH\",\"type\":\"Ripemd160\"}," ++
    "{\"name\":\"_changeAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}]";

const settle_with_change_and_new_amount =
    "\"name\":\"settle\",\"params\":[" ++
    "{\"name\":\"amount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_changePKH\",\"type\":\"Ripemd160\"}," ++
    "{\"name\":\"_changeAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_newAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}]";

fn abiContains(source: []const u8, file: []const u8, needle: []const u8) !void {
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, source, file);
    defer result.deinit(allocator);
    const json = result.artifact_json orelse return error.TestExpectedJson;
    if (std.mem.indexOf(u8, json, needle) == null) {
        std.debug.print("expected ABI fragment not found:\n  {s}\n", .{needle});
        return error.TestUnexpectedResult;
    }
    try std.testing.expect(result.script_hex.len > 0);
}

// Control — already green; guards against over-correction.
test "R-021 control: a bare-statement addOutput keeps its continuation params" {
    try abiContains(stmt_output, "StmtOutput.runar.ts", settle_with_change);
}

// Shape 1 — output intrinsic behind a var-decl initialiser.
test "R-021: addOutput behind a var-decl initialiser declares the change params" {
    try abiContains(vardecl_output, "VarDeclOutput.runar.ts", settle_with_change);
}

// Shape 2 — state mutation behind a var-decl initialiser.
test "R-021: a state mutation behind a var-decl initialiser is not terminal" {
    try abiContains(
        vardecl_mutation,
        "VarDeclMutation.runar.ts",
        settle_with_change_and_new_amount,
    );
}
