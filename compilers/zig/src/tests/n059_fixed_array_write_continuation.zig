//! N-059: a FixedArray ELEMENT write must declare the state continuation, and
//! must lower identically on every surface.
//!
//! Same funds-safety class as `sol_bare_property_write_continuation.zig`, one
//! layer up the pipeline. `passes/expand_fixed_arrays.zig` desugars
//! `this.grid[0][1] = v` into a scalar write to the synthetic leaf property
//! `grid__0__1` — but every `Assign` it synthesises in `rewriteIndexAssign` /
//! `buildWriteDispatchIf` was built WITHOUT `target_is_property`, which
//! defaults to false. The rewritten statement therefore looked like a write to
//! a LOCAL named `grid__0__1`.
//!
//! ANF lowering did not notice, because `lowerBinding`'s `writes_property` has
//! an `(!isLocal and isProperty)` fallback and the synthetic leaf IS a property
//! by then — so `update_prop grid__0__1` came out correct. `methodMutatesState`
//! -> `stmtMutatesStateRec` has NO such fallback (deliberately: `7dfb8c07` made
//! it key strictly on the flag so a shadowing local can't fake a state write).
//! The two halves of the tier therefore disagreed: the body wrote state, the
//! shape decision said the method was TERMINAL.
//!
//! A terminal stateful method carries no continuation covenant at all: no
//! `_changePKH` / `_changeAmount` / `_newAmount` parameters, no `hashOutputs`
//! binding, no `_codePart` witness. A spender is unconstrained in where the
//! funds go — the whole point of `StatefulSmartContract`.
//!
//! Measured on `TS_SRC` below, fold-OFF, via each tier's CLI before the fix:
//!
//!     ts / go / rust / python / ruby / java (.ts)   3361 bytes
//!     zig (.ts, before)                             2467 bytes, terminal ABI
//!
//! Two further surface-local defects fall out of the same fixture and are
//! pinned here too:
//!
//!   * `passes/parse_sol.zig` and `passes/parse_move.zig` had no
//!     `.index_access` arm in `buildAssignment`, so `this.grid[0][0] = v`
//!     became `Assign{ target = "unknown", index_target = null }`. The
//!     expansion pass never saw an index target, the write lowered to
//!     `update_prop "unknown"`, and the element assignment was lost outright.
//!     Every other Zig-tier surface parser already carried the arm.
//!
//!   * `passes/parse_zig.zig` left the receiver of a property access as
//!     `self` where all eight peer parsers in this tier normalise it to
//!     `this`. `tryResolveLiteralIndexChain` requires the `this` root, so on
//!     the `.runar.zig` surface a nested chain resolved only its innermost
//!     level: reads produced `__array_access(load_prop grid__0, 0)` and stack
//!     lowering then refused the contract outright
//!     (`LoadPropNoConstructorSlot` on `grid__0`).
//!
//! NOT fixed here, deliberately: the seven tiers disagree FOUR ways on how to
//! spell the per-leaf FixedArray regrouping metadata in the emitted ANF IR --
//! `go` writes `syntheticArrayChain`, `rust` writes `__syntheticArrayChain`,
//! `ruby` writes `synthetic_array_chain`, and `ts` / `python` / `java` / `zig`
//! write nothing at all. The script HEX agrees across all seven (see the
//! cross-surface tests below); only the IR does not. Moving Zig into any one
//! of those camps trades one divergence for another, so the spelling stays as
//! it is until the project picks one for all seven. Escalated as its own item.
//!
//! The tests below pin behaviour, not goldens: the ABI shape for the write
//! path, and cross-surface byte equality for the rest.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

/// Nested 2x2 FixedArray, written through a literal index chain.
const TS_SRC =
    \\class Grid2x2 extends StatefulSmartContract {
    \\  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];
    \\
    \\  constructor() {
    \\    super();
    \\  }
    \\
    \\  public set01(v: bigint) {
    \\    this.grid[0][1] = v;
    \\    assert(true);
    \\  }
    \\}
;

/// The same contract on the Solidity surface. Solidity's array-of-arrays type
/// reads outer-to-inner left-to-right, so `int[2][2]` is the same shape as the
/// TypeScript `FixedArray<FixedArray<bigint, 2>, 2>` for the symmetric case.
const SOL_SRC =
    \\pragma runar ^0.1.0;
    \\
    \\contract Grid2x2 is StatefulSmartContract {
    \\    bigint[2][2] grid = [[0, 0], [0, 0]];
    \\
    \\    constructor() {}
    \\
    \\    function set01(bigint v) public {
    \\        this.grid[0][1] = v;
    \\        require(true);
    \\    }
    \\}
;

/// The same contract on the Move surface. Move has no fixed-length array, so
/// the Rúnar Move frontend spells the shape with a synthetic
/// `FixedArray<T, N>` generic, as `examples/move/fixed-array-nested` does.
const MOVE_SRC =
    \\module Grid2x2 {
    \\    use runar::StatefulSmartContract;
    \\    use runar::types::{};
    \\
    \\    resource struct Grid2x2 {
    \\        grid: &mut FixedArray<FixedArray<bigint, 2>, 2> = [[0, 0], [0, 0]],
    \\    }
    \\
    \\    public fun set01(v: bigint) {
    \\        self.grid[0][1] = v;
    \\        assert!(true, 0);
    \\    }
    \\}
;

/// The same contract on the native Zig surface.
const ZIG_SRC =
    \\const runar = @import("runar");
    \\
    \\pub const Grid2x2 = struct {
    \\    pub const Contract = runar.StatefulSmartContract;
    \\
    \\    grid: [2][2]i64 = .{ .{ 0, 0 }, .{ 0, 0 } },
    \\
    \\    pub fn init() Grid2x2 {
    \\        return .{};
    \\    }
    \\
    \\    pub fn set01(self: *Grid2x2, v: i64) void {
    \\        self.grid[0][1] = v;
    \\        runar.assert(true);
    \\    }
    \\};
;

/// A single-level FixedArray, to prove the defect was never about nesting.
const FLAT_TS_SRC =
    \\class Row2 extends StatefulSmartContract {
    \\  row: FixedArray<bigint, 2> = [0n, 0n];
    \\
    \\  constructor() {
    \\    super();
    \\  }
    \\
    \\  public set0(v: bigint) {
    \\    this.row[0] = v;
    \\    assert(true);
    \\  }
    \\}
;

/// A runtime (non-literal) index write, which `rewriteIndexAssign` lowers
/// through `buildWriteDispatchIf` instead of a direct assignment. That path
/// synthesises its `Assign` nodes separately and dropped the flag too.
const RUNTIME_INDEX_TS_SRC =
    \\class Row2Dyn extends StatefulSmartContract {
    \\  row: FixedArray<bigint, 2> = [0n, 0n];
    \\
    \\  constructor() {
    \\    super();
    \\  }
    \\
    \\  public setAt(i: bigint, v: bigint) {
    \\    this.row[i] = v;
    \\    assert(true);
    \\  }
    \\}
;

/// The continuation parameters a state-writing method must declare. Their
/// absence is the defect: no continuation parameters means no covenant.
const set01_continuation =
    "\"name\":\"set01\",\"params\":[" ++
    "{\"name\":\"v\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_changePKH\",\"type\":\"Ripemd160\"}," ++
    "{\"name\":\"_changeAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_newAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}]," ++
    "\"isPublic\":true,\"usesCodePart\":true";

const set0_continuation =
    "\"name\":\"set0\",\"params\":[" ++
    "{\"name\":\"v\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_changePKH\",\"type\":\"Ripemd160\"}," ++
    "{\"name\":\"_changeAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_newAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}]," ++
    "\"isPublic\":true,\"usesCodePart\":true";

const setAt_continuation =
    "\"name\":\"setAt\",\"params\":[" ++
    "{\"name\":\"i\",\"type\":\"bigint\"}," ++
    "{\"name\":\"v\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_changePKH\",\"type\":\"Ripemd160\"}," ++
    "{\"name\":\"_changeAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"_newAmount\",\"type\":\"bigint\"}," ++
    "{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}]," ++
    "\"isPublic\":true,\"usesCodePart\":true";

fn expectContinuation(src: []const u8, file_name: []const u8, fragment: []const u8) !void {
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, src, file_name);
    defer result.deinit(allocator);
    const json = result.artifact_json orelse return error.TestExpectedJson;
    if (std.mem.indexOf(u8, json, fragment) == null) {
        std.debug.print(
            "{s}: expected continuation ABI fragment not found:\n  {s}\n",
            .{ file_name, fragment },
        );
        return error.TestUnexpectedResult;
    }
    // R-010's hoisted `OP_NOP OP_CODESEPARATOR` prologue is emitted for, and
    // only for, a contract that authenticates a `_codePart` witness — the
    // on-the-wire evidence that the continuation covenant is really there and
    // not just named in the ABI.
    try std.testing.expect(std.mem.startsWith(u8, result.script_hex, "61ab"));
}

test "a nested FixedArray element write declares the state continuation" {
    try expectContinuation(TS_SRC, "Grid2x2.runar.ts", set01_continuation);
}

test "a single-level FixedArray element write declares the state continuation" {
    try expectContinuation(FLAT_TS_SRC, "Row2.runar.ts", set0_continuation);
}

test "a runtime-index FixedArray element write declares the state continuation" {
    try expectContinuation(RUNTIME_INDEX_TS_SRC, "Row2Dyn.runar.ts", setAt_continuation);
}

test "the Solidity surface lowers a nested FixedArray write like TypeScript" {
    const allocator = std.testing.allocator;
    const ts = try compiler_api.compileSource(allocator, TS_SRC, "Grid2x2.runar.ts");
    defer ts.deinit(allocator);
    const sol = try compiler_api.compileSource(allocator, SOL_SRC, "Grid2x2.runar.sol");
    defer sol.deinit(allocator);
    try std.testing.expectEqualStrings(ts.script_hex, sol.script_hex);
}

test "the Move surface lowers a nested FixedArray write like TypeScript" {
    const allocator = std.testing.allocator;
    const ts = try compiler_api.compileSource(allocator, TS_SRC, "Grid2x2.runar.ts");
    defer ts.deinit(allocator);
    const move = try compiler_api.compileSource(allocator, MOVE_SRC, "Grid2x2.runar.move");
    defer move.deinit(allocator);
    try std.testing.expectEqualStrings(ts.script_hex, move.script_hex);
}

test "the Zig surface lowers a nested FixedArray write like TypeScript" {
    const allocator = std.testing.allocator;
    const ts = try compiler_api.compileSource(allocator, TS_SRC, "Grid2x2.runar.ts");
    defer ts.deinit(allocator);
    const zig = try compiler_api.compileSource(allocator, ZIG_SRC, "Grid2x2.runar.zig");
    defer zig.deinit(allocator);
    try std.testing.expectEqualStrings(ts.script_hex, zig.script_hex);
}
