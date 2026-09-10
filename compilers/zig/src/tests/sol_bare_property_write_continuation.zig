//! A Solidity-surface write to a bare state variable must declare the state
//! continuation, exactly as the `this.`-prefixed write on every other surface
//! does.
//!
//! Solidity references state variables WITHOUT a `this.` prefix, so
//! `passes/parse_sol.zig` produces a bare `.identifier` where the ts / go /
//! rust / python / ruby / java surfaces produce a `.property_access`. Nothing
//! in this tier reconciled the two: ANF lowering papered over it with the
//! `(!isLocal and isProperty)` fallback in `lowerBinding`'s `writes_property`,
//! so reads and `update_prop` writes came out right, and the divergence stayed
//! invisible.
//!
//! `7dfb8c07` (R-028 sibling) then keyed `methodMutatesState` ->
//! `stmtMutatesStateRec` STRICTLY on `Assign.target_is_property`, matching the
//! reference's `stmt.target.kind === 'property_access'`. Correct for every
//! surface that sets the flag — and on the Solidity surface it made every
//! bare state-variable write invisible to the continuation-shape decision.
//! The method was classified TERMINAL, so the emitted locking script carried
//! NO state-continuation covenant at all: no `_changePKH` / `_changeAmount` /
//! `_newAmount` parameters, no `hashOutputs` binding, no `_codePart` witness,
//! and therefore none of R-010's `_codePart` authentication or N-043's length
//! pin. A spender of such a contract is unconstrained in where the funds go.
//!
//! Measured on `SOL_SRC` / `TS_SRC` below, fold-ON, via each tier's CLI:
//!
//!     ts / go / rust / python / ruby / java (.sol)   684 bytes
//!     zig (.sol, before)                             470 bytes, terminal ABI
//!     every tier including zig (.ts)                 684 bytes
//!
//! The reference tiers do not have the defect because their Solidity parsers
//! rewrite bare property references into property-access nodes before the
//! shape decision runs (`resolvePropertyAccess` in
//! `packages/runar-compiler/src/passes/01-parse-sol.ts`,
//! `solRewriteStmtBareProps` in `compilers/go/frontend/parser_sol.go`,
//! `sol_rewrite_stmt_bare_props` in `compilers/rust/src/frontend/parser_sol.rs`).
//! Zig was the only tier without that pass.
//!
//! The tests below pin the invariant without a hardcoded golden: the same
//! contract written on the Solidity surface and on the TypeScript surface must
//! compile to the same bytes, since both lower to the same AST. The shadowing
//! probe guards the OTHER direction — R-028 sibling's own fix — so a repair
//! here cannot go back to counting a local that merely shadows a property.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// A stateful contract whose public method writes the mutable property `a`
/// through Solidity's bare state-variable syntax.
const SOL_SRC =
    \\pragma runar ^0.1.0;
    \\
    \\contract S1 is StatefulSmartContract {
    \\    int a;
    \\
    \\    constructor(int _a) {
    \\        a = _a;
    \\    }
    \\
    \\    function settle(int amount) public {
    \\        a = a + amount;
    \\        require(a > 0);
    \\    }
    \\}
;

/// The same contract on the TypeScript surface — the reference shape, where
/// the write is unambiguously a property access.
const TS_SRC =
    \\class S1 extends StatefulSmartContract {
    \\  a: bigint;
    \\
    \\  constructor(a: bigint) {
    \\    super(a);
    \\    this.a = a;
    \\  }
    \\
    \\  public settle(amount: bigint) {
    \\    this.a = this.a + amount;
    \\    assert(this.a > 0n);
    \\  }
    \\}
;

/// A Solidity method whose `a` is a LOCAL shadowing the mutable property `a`.
/// It writes no state, so it must stay terminal — this is R-028 sibling's
/// invariant, restated on the surface that motivates the fix above.
const SOL_SHADOW_SRC =
    \\pragma runar ^0.1.0;
    \\
    \\contract S2 is StatefulSmartContract {
    \\    int a;
    \\
    \\    constructor(int _a) {
    \\        a = _a;
    \\    }
    \\
    \\    function settle(int amount) public {
    \\        int a = amount;
    \\        a = a + 1;
    \\        require(a > 0);
    \\    }
    \\}
;

/// The continuation parameters a method that writes state must declare. Their
/// absence is the whole defect: no continuation parameters means no covenant.
const settle_continuation =
    "\"name\":\"settle\",\"params\":[" ++
    "{\"name\":\"amount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_changePKH\",\"type\":\"Ripemd160\"}," ++
    "{\"name\":\"_changeAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_newAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}]," ++
    "\"isPublic\":true,\"usesCodePart\":true";

/// The terminal ABI: no continuation parameters, and no `_codePart` witness.
const settle_terminal =
    "\"name\":\"settle\",\"params\":[" ++
    "{\"name\":\"amount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}],\"isPublic\":true}";

test "a bare Solidity state-variable write declares the state continuation" {
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, SOL_SRC, "S1.runar.sol");
    defer result.deinit(allocator);
    const json = result.artifact_json orelse return error.TestExpectedJson;
    if (std.mem.indexOf(u8, json, settle_continuation) == null) {
        std.debug.print("expected continuation ABI fragment not found:\n  {s}\n", .{settle_continuation});
        return error.TestUnexpectedResult;
    }
}

test "the Solidity and TypeScript surfaces compile the same contract to the same bytes" {
    const allocator = std.testing.allocator;
    const sol = try compiler_api.compileSource(allocator, SOL_SRC, "S1.runar.sol");
    defer sol.deinit(allocator);
    const ts = try compiler_api.compileSource(allocator, TS_SRC, "S1.runar.ts");
    defer ts.deinit(allocator);
    try std.testing.expectEqualStrings(ts.script_hex, sol.script_hex);
}

test "the Solidity surface carries R-010's hoisted OP_CODESEPARATOR prologue" {
    // `61ab` = OP_NOP OP_CODESEPARATOR at offset 0..1 of the locking script.
    // R-010 emits it for, and only for, a contract that authenticates a
    // `_codePart` witness, so its presence is the on-the-wire evidence that
    // `emitCodePartAuthentication` ran on this surface.
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, SOL_SRC, "S1.runar.sol");
    defer result.deinit(allocator);
    try std.testing.expect(std.mem.startsWith(u8, result.script_hex, "61ab"));
}

test "a Solidity local shadowing a mutable property leaves the method terminal" {
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, SOL_SHADOW_SRC, "S2.runar.sol");
    defer result.deinit(allocator);
    const json = result.artifact_json orelse return error.TestExpectedJson;
    if (std.mem.indexOf(u8, json, settle_terminal) == null) {
        std.debug.print("expected terminal ABI fragment not found:\n  {s}\n", .{settle_terminal});
        return error.TestUnexpectedResult;
    }
}
