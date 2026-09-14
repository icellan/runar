//! R-073 / CL-BUG-168 — a FixedArray ELEMENT write must be type-checked.
//!
//! `passes/typecheck.zig`'s `.assign` arm carried two early returns that skip
//! the subtype check:
//!
//!   * the `index_target != null` arm — ANY indexed write, checked here;
//!   * the `target_type == .fixed_array` arm — a whole-array target.
//!
//! The filed finding named the second. The arm that actually fires for the
//! repro is the FIRST: `this.cells[0] = v` carries an `index_target`, so the
//! statement returned before `target_type` was even computed. Confirmed by
//! disabling the second arm alone and rebuilding — the repro still compiled to
//! a full 2548-hex-char locking script.
//!
//! The second arm is not the bug and is left alone: whole-array reassignment is
//! not a legal Rúnar program on any surface. `passes/expand_fixed_arrays.zig`
//! refuses `this.cells = other` outright ("cannot reassign entire FixedArray
//! property"), so nothing reaches codegen through it. Pinned below.
//!
//! Measured on `BAD_LITERAL_INDEX` via each tier's CLI before the fix:
//!
//!     go / ts / rust / python / ruby / java   REJECT
//!         "type 'ByteString' is not assignable to type 'bigint'"
//!     zig (before)                            ACCEPTS, 2548 hex chars
//!
//! The element type cannot be recovered from `inferExprType`: its
//! `.index_access` arm returns `.unknown` unconditionally, and the N-019
//! tripwire in `passes/typecheck.zig` requires that it keep doing so (teaching
//! it to type element READS would make `this.board[i]++` compile with the N-019
//! defect intact). The fix therefore reads the element type off the declared
//! property instead of off the expression, which leaves reads untouched.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const parse_sol = @import("../passes/parse_sol.zig");
const parse_python = @import("../passes/parse_python.zig");
const typecheck = @import("../passes/typecheck.zig");
const compiler_api = @import("../compiler_api.zig");

/// The cross-tier diagnostic, spelled exactly as Go / Python / Ruby / Java emit
/// it. Asserting on the MESSAGE rather than on "some error occurred" is the
/// point: a rejection for an unrelated reason would otherwise pass this test
/// and stop guarding anything.
const MISMATCH = "type 'ByteString' is not assignable to type 'bigint'";

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// The filed repro: literal index, wrong element type.
const BAD_LITERAL_INDEX =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class CellProbe extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public setBad(v: ByteString) {
    \\    assert(this.owner > 0n);
    \\    this.cells[0] = v;
    \\  }
    \\}
;

/// The same write through a RUNTIME index, which `expand_fixed_arrays` lowers
/// through a different rewrite (`buildWriteDispatchIf`). Typecheck runs before
/// that split, so both shapes must be refused at the same place.
const BAD_RUNTIME_INDEX =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class CellProbeDyn extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public setBad(i: bigint, v: ByteString) {
    \\    assert(this.owner > 0n);
    \\    this.cells[i] = v;
    \\  }
    \\}
;

/// The mirror image: a `FixedArray<ByteString, 2>` written with a bigint.
const BAD_REVERSED =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class WordProbe extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  words: FixedArray<ByteString, 2> = ["00", "00"];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public setBad(v: bigint) {
    \\    assert(this.owner > 0n);
    \\    this.words[0] = v;
    \\  }
    \\}
;

/// Scalar control: the mismatch this tier ALREADY rejected. Proves the scalar
/// path did not regress, and that the indexed path now produces the same text.
const BAD_SCALAR =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class ScalarCtl extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  tag: bigint = 0n;
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public setBad(v: ByteString) {
    \\    assert(this.owner > 0n);
    \\    this.tag = v;
    \\  }
    \\}
;

/// Positive control 1: correct element writes (literal AND runtime index) plus
/// an element READ. Must keep compiling, byte-for-byte unchanged.
const GOOD_BIGINT_CELLS =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class PosIdx extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public setGood(i: bigint, v: bigint) {
    \\    assert(this.owner > 0n);
    \\    this.cells[0] = v;
    \\    this.cells[i] = v;
    \\  }
    \\  public readCell() {
    \\    assert(this.cells[1] == 0n);
    \\  }
    \\}
;

/// Positive control 2: a `FixedArray<ByteString, 2>` written with a ByteString.
const GOOD_BYTESTRING_WORDS =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class PosWords extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  words: FixedArray<ByteString, 2> = ["00", "00"];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public setWord(w: ByteString) {
    \\    assert(this.owner > 0n);
    \\    this.words[0] = w;
    \\  }
    \\}
;

/// A method PARAMETER sharing the array property's name must not disarm the
/// check: `this.cells[0]` is still the property. Gating on
/// `env.lookup(target) == null` alone would have skipped it, which is how Go
/// (whose target is the whole `this.cells[0]` expression) behaves — it rejects
/// this source.
const SHADOWED_NAME_BAD =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class Shadow extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public setBad(cells: ByteString, v: ByteString) {
    \\    assert(this.owner > 0n);
    \\    this.cells[0] = v;
    \\    assert(cells != "00");
    \\  }
    \\}
;

/// Whole-array reassignment — the shape the SECOND early return guards. Illegal
/// in the language; `expand_fixed_arrays` is what refuses it.
const WHOLE_ARRAY_ASSIGN =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class WholeArr extends StatefulSmartContract {
    \\  readonly owner: bigint;
    \\  cells: FixedArray<bigint, 3> = [0n, 0n, 0n];
    \\  constructor(owner: bigint) {
    \\    super(owner);
    \\    this.owner = owner;
    \\  }
    \\  public setWhole(v: ByteString) {
    \\    assert(this.owner > 0n);
    \\    this.cells = v;
    \\  }
    \\}
;

/// Documented residual gap — NESTED chains. `this.grid[0][1] = v` parses with
/// `target = "unknown"` (the index-access object is itself an index access),
/// and a nested property records `.fixed_array` as its element type with the
/// LEAF type discarded at parse time in all nine of this tier's surface
/// parsers. Go rejects this source; Zig still accepts it.
///
/// Closing it means adding a leaf-element field to `PropertyNode` and setting
/// it in all nine parsers — a wider change than CL-BUG-168, and one that also
/// has to reckon with `expand_fixed_arrays.buildMeta` hardcoding `.bigint` as
/// the nested leaf type. Tracked separately; pinned here so the gap is visible
/// and whoever closes it gets a signal from this file.
const NESTED_BAD =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class Nested extends StatefulSmartContract {
    \\  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];
    \\  constructor() {
    \\    super();
    \\  }
    \\  public setBad(v: ByteString) {
    \\    this.grid[0][1] = v;
    \\    assert(true);
    \\  }
    \\}
;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse + typecheck a `.runar.ts` source and report whether any type error
/// contains `needle`. A parse failure is surfaced as an error rather than
/// silently counted as "rejected" — a fixture that stops parsing would
/// otherwise make this whole file vacuous.
fn typecheckHasError(a: std.mem.Allocator, src: []const u8, needle: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();

    const parsed = parse_ts.parseTs(w, src, "R073.runar.ts");
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

/// Number of type errors a source produces. Used to prove the fix adds exactly
/// one diagnostic and not a cascade.
fn typecheckErrorCount(a: std.mem.Allocator, src: []const u8) !usize {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = parse_ts.parseTs(w, src, "R073.runar.ts");
    if (parsed.contract == null) return error.TestFixtureDidNotParse;
    const result = try typecheck.typeCheck(w, parsed.contract.?);
    return result.errors.len;
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

test "R-073: literal-index write of a ByteString into FixedArray<bigint,3> is rejected" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(a, BAD_LITERAL_INDEX, MISMATCH));
}

test "R-073: runtime-index write of a ByteString into FixedArray<bigint,3> is rejected" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(a, BAD_RUNTIME_INDEX, MISMATCH));
}

test "R-073: bigint written into FixedArray<ByteString,2> is rejected" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(
        a,
        BAD_REVERSED,
        "type 'bigint' is not assignable to type 'ByteString'",
    ));
}

test "R-073: the whole compile refuses the repro, not just the typecheck pass" {
    const a = std.testing.allocator;
    try std.testing.expectError(
        error.TypeCheckFailed,
        compiler_api.compileSource(a, BAD_LITERAL_INDEX, "CellProbe.runar.ts"),
    );
}

test "R-073: one diagnostic, not a cascade" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 1), try typecheckErrorCount(a, BAD_LITERAL_INDEX));
}

// ---------------------------------------------------------------------------
// Cross-surface: the rule belongs to the language, not to the TypeScript parser
// ---------------------------------------------------------------------------

test "R-073: the Solidity surface is refused too" {
    const a = std.testing.allocator;
    const src =
        \\pragma runar ^0.1.0;
        \\
        \\contract CellProbe is StatefulSmartContract {
        \\    bigint[3] cells = [0, 0, 0];
        \\
        \\    constructor() {}
        \\
        \\    function setBad(bytes v) public {
        \\        this.cells[0] = v;
        \\        require(true);
        \\    }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = parse_sol.parseSol(w, src, "CellProbe.runar.sol");
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    const result = try typecheck.typeCheck(w, parsed.contract orelse return error.TestFixtureDidNotParse);
    var saw = false;
    for (result.errors) |msg| {
        if (std.mem.indexOf(u8, msg, MISMATCH) != null) saw = true;
    }
    try std.testing.expect(saw);
}

test "R-073: the Python surface is refused too" {
    const a = std.testing.allocator;
    const src =
        \\from runar import StatefulSmartContract, FixedArray, ByteString, assert_
        \\
        \\class CellProbe(StatefulSmartContract):
        \\    cells: FixedArray[int, 3] = [0, 0, 0]
        \\
        \\    def __init__(self):
        \\        super().__init__()
        \\
        \\    @public
        \\    def set_bad(self, v: ByteString):
        \\        self.cells[0] = v
        \\        assert_(True)
    ;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = parse_python.parsePython(w, src, "CellProbe.runar.py");
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
        return error.TestFixtureDidNotParse;
    }
    const result = try typecheck.typeCheck(w, parsed.contract orelse return error.TestFixtureDidNotParse);
    var saw = false;
    for (result.errors) |msg| {
        if (std.mem.indexOf(u8, msg, MISMATCH) != null) saw = true;
    }
    try std.testing.expect(saw);
}

// ---------------------------------------------------------------------------
// Controls that must NOT have moved
// ---------------------------------------------------------------------------

test "R-073 control: the scalar-property mismatch still rejects, with the same text" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(a, BAD_SCALAR, MISMATCH));
}

test "R-073 control: correct element writes and an element read still compile" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), try typecheckErrorCount(a, GOOD_BIGINT_CELLS));
    const hex = try compileHex(a, GOOD_BIGINT_CELLS, "PosIdx.runar.ts");
    defer a.free(hex);
    // Byte-for-byte pin, captured from the pre-fix binary.
    try std.testing.expectEqual(@as(usize, 2548), hex.len);
    try std.testing.expect(std.mem.startsWith(u8, hex, "61ab76009c63757676aa517f"));
}

test "R-073 control: FixedArray<ByteString,2> written with a ByteString still compiles" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), try typecheckErrorCount(a, GOOD_BYTESTRING_WORDS));
    const hex = try compileHex(a, GOOD_BYTESTRING_WORDS, "PosWords.runar.ts");
    defer a.free(hex);
    try std.testing.expectEqual(@as(usize, 1778), hex.len);
    try std.testing.expect(std.mem.startsWith(u8, hex, "61ab7676aa517f517f"));
}

test "R-073: a parameter sharing the array's name does not disarm the check" {
    const a = std.testing.allocator;
    try std.testing.expect(try typecheckHasError(a, SHADOWED_NAME_BAD, MISMATCH));
}

test "R-073 control: whole-array reassignment is refused by expand_fixed_arrays" {
    const a = std.testing.allocator;
    // Typecheck deliberately stays quiet here (second early return) ...
    try std.testing.expectEqual(@as(usize, 0), try typecheckErrorCount(a, WHOLE_ARRAY_ASSIGN));
    // ... because the later pass refuses the program outright.
    try std.testing.expectError(
        error.ValidationFailed,
        compiler_api.compileSource(a, WHOLE_ARRAY_ASSIGN, "WholeArr.runar.ts"),
    );
}

// ---------------------------------------------------------------------------
// Residual gap, pinned
// ---------------------------------------------------------------------------

test "R-073 gap: a NESTED chain is still unchecked (Go rejects it, this tier does not)" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), try typecheckErrorCount(a, NESTED_BAD));
    const hex = try compileHex(a, NESTED_BAD, "Nested.runar.ts");
    defer a.free(hex);
    try std.testing.expect(hex.len > 0);
    // WHEN THIS TEST STARTS FAILING the nested leaf type has become available
    // and the gap is closed — delete this test rather than relaxing it.
}
