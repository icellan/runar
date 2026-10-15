//! N-061 / R-065 regression guard for the Zig tier: the for-loop `update`
//! clause is parsed and then THROWN AWAY at parse time, so nothing downstream
//! can look at it.
//!
//! `types.ForStmt` stores a pre-digested loop shape — `{var_name, init_value,
//! bound, descending, inclusive, body}` — and the surface parsers derive
//! `descending` from the COMPARISON DIRECTION, never from the update. Every
//! parser's update branch is a bare `_ = self.parseExpression()`. So any update
//! clause at all was coerced to a unit step and discarded, and four distinct
//! failures were indistinguishable from a correct compile:
//!
//!   - `while (i < 5) : (i += 2)` (.runar.zig), `i = i + 2` (.runar.move) and
//!     `i = i.plus(Bigint.of(2))` (.runar.java) unrolled 5 times over
//!     i = 0..4 instead of 3 times over i = 0,2,4 — byte-identical to the
//!     unit-step loop, with no diagnostic.
//!   - `for (let i = 0n; i < 3n; undefinedFn())` compiled clean. A nonexistent
//!     function name raised nothing — a hole in the rule that only Rúnar
//!     builtins and contract methods are callable.
//!   - `for (let i = 0n; i < 3n; this.count++)` silently DROPPED the state
//!     write from the emitted script.
//!   - `for (let i = 0n; i < 3n; j++)` advanced a variable the loop model
//!     never binds.
//!
//! `spec/grammar.md` is authoritative and permits only the unit forms: its
//! ForStatement production ends `Identifier ( '++' | '--' )`, and its Statement
//! Restrictions say "The loop variable MUST use simple increment (`++`) or
//! decrement (`--`)". So rejecting is the fix rather than lowering: the ANF
//! `loop` node can express exactly `{count, iterVar, start, step, body}` and
//! synthesizes the iterator on unrolled iteration k as `start + k*step`. There
//! is no slot for an arbitrary update statement, and appending the update's
//! lowering to the loop body would re-emit `i++` as a dead binding on every
//! loop that already compiles correctly.
//!
//! The diagnostic text is shared VERBATIM with the other six tiers
//! (`compilers/rust/src/frontend/validator.rs` is the source of truth).
//!
//! What these tests do NOT prove: nothing here says the update clause is
//! *lowered*; the contract is that a non-representable update is a compile
//! error instead of silent output. The controls pin the `bounded-loop` shape
//! only — they show the fix refuses nothing that compiled before.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const parse_zig = @import("../passes/parse_zig.zig");
const parse_move = @import("../passes/parse_move.zig");
const parse_java = @import("../passes/parse_java.zig");
const parse_sol = @import("../passes/parse_sol.zig");
const parse_go = @import("../passes/parse_go.zig");
const parse_python = @import("../passes/parse_python.zig");
const parse_rust = @import("../passes/parse_rust.zig");
const parse_ruby = @import("../passes/parse_ruby.zig");
const validate = @import("../passes/validate.zig");
const compiler_api = @import("../compiler_api.zig");

const Allocator = std.mem.Allocator;

/// The one correct answer. `bounded-loop` sums `start + i` for i in 0..4 and
/// asserts the total; all nine frontends lower to these exact 42 bytes.
const bounded_loop_hex = "000052797b7c937c935152797b7c937c935252797b7c937c935352797b7c937c93547b7b7c937c93009c";

/// The cross-tier diagnostic substring. Pinned in all seven tiers.
const loop_update_diagnostic = "must advance the loop variable by one";

// ---------------------------------------------------------------------------
// The nine surface spellings of `bounded-loop`
// ---------------------------------------------------------------------------

const src_ts =
    \\import { SmartContract, assert } from 'runar-lang';
    \\
    \\class BoundedLoop extends SmartContract {
    \\  readonly expectedSum: bigint;
    \\
    \\  constructor(expectedSum: bigint) {
    \\    super(expectedSum);
    \\    this.expectedSum = expectedSum;
    \\  }
    \\
    \\  public verify(start: bigint): void {
    \\    let sum: bigint = 0n;
    \\    for (let i: bigint = 0n; i < 5; i++) {
    \\      sum = sum + start + i;
    \\    }
    \\    assert(sum === this.expectedSum);
    \\  }
    \\}
;

const src_sol =
    \\pragma runar ^0.1.0;
    \\
    \\contract BoundedLoop is SmartContract {
    \\    int immutable expectedSum;
    \\
    \\    constructor(int _expectedSum) {
    \\        expectedSum = _expectedSum;
    \\    }
    \\
    \\    function verify(int start) public {
    \\        int sum = 0;
    \\        for (int i = 0; i < 5; i++) {
    \\            sum = sum + start + i;
    \\        }
    \\        require(sum == expectedSum);
    \\    }
    \\}
;

const src_go =
    \\//go:build ignore
    \\
    \\package contract
    \\
    \\import "runar"
    \\
    \\type BoundedLoop struct {
    \\    runar.SmartContract
    \\    ExpectedSum runar.Int `runar:"readonly"`
    \\}
    \\
    \\func (c *BoundedLoop) Verify(start runar.Int) {
    \\    sum := runar.Int(0)
    \\    for i := runar.Int(0); i < 5; i++ {
    \\        sum = sum + start + i
    \\    }
    \\    runar.Assert(sum == c.ExpectedSum)
    \\}
;

const src_move =
    \\module BoundedLoop {
    \\    use runar::types::{Int};
    \\
    \\    struct BoundedLoop {
    \\        expected_sum: Int,
    \\    }
    \\
    \\    public fun verify(contract: &BoundedLoop, start: Int) {
    \\        let sum: Int = 0;
    \\        let i: Int = 0;
    \\        while (i < 5) {
    \\            sum = sum + start + i;
    \\            i = i + 1;
    \\        };
    \\        assert_eq!(sum, contract.expected_sum);
    \\    }
    \\}
;

const src_zig =
    \\const runar = @import("runar");
    \\
    \\pub const BoundedLoop = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    expectedSum: i64,
    \\
    \\    pub fn init(expectedSum: i64) BoundedLoop {
    \\        return .{ .expectedSum = expectedSum };
    \\    }
    \\
    \\    pub fn verify(self: *const BoundedLoop, start: i64) void {
    \\        var sum: i64 = 0;
    \\        var i: i64 = 0;
    \\        while (i < 5) : (i += 1) {
    \\            sum = sum + start + i;
    \\        }
    \\        runar.assert(sum == self.expectedSum);
    \\    }
    \\};
;

const src_java =
    \\package runar.examples.boundedloop;
    \\
    \\import runar.lang.SmartContract;
    \\import runar.lang.annotations.Public;
    \\import runar.lang.annotations.Readonly;
    \\import runar.lang.types.Bigint;
    \\
    \\import static runar.lang.Builtins.assertThat;
    \\
    \\class BoundedLoop extends SmartContract {
    \\
    \\    @Readonly Bigint expectedSum;
    \\
    \\    BoundedLoop(Bigint expectedSum) {
    \\        super(expectedSum);
    \\        this.expectedSum = expectedSum;
    \\    }
    \\
    \\    @Public
    \\    void verify(Bigint start) {
    \\        Bigint sum = Bigint.ZERO;
    \\        for (Bigint i = Bigint.ZERO; i.lt(Bigint.of(5)); i = i.plus(Bigint.ONE)) {
    \\            sum = sum.plus(start).plus(i);
    \\        }
    \\        assertThat(sum.eq(this.expectedSum));
    \\    }
    \\}
;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compile a source string all the way to hex. Returns null when the compile
/// was refused (by any pass).
fn compileHex(alloc: Allocator, source: []const u8, file_name: []const u8) ?[]const u8 {
    const result = compiler_api.compileSource(alloc, source, file_name) catch return null;
    return result.script_hex;
}

/// Assert the source is refused AND that the refusal carries the shared
/// cross-tier diagnostic, not some incidental parse error.
fn expectRejectedWithSharedDiagnostic(
    alloc: Allocator,
    source: []const u8,
    file_name: []const u8,
) !void {
    return expectRejectedWithDiagnostic(alloc, source, file_name, loop_update_diagnostic);
}

/// The Move surface's shape diagnostic, verbatim from `parse_move.zig` and
/// from the six peer tiers.
const move_while_shape_diagnostic = "must be a bounded counting loop";

fn expectRejectedWithDiagnostic(
    alloc: Allocator,
    source: []const u8,
    file_name: []const u8,
    expected: []const u8,
) !void {
    if (compileHex(alloc, source, file_name)) |hex| {
        std.debug.print(
            "{s}: a non-representable loop update must not compile, got {d} hex chars\n",
            .{ file_name, hex.len },
        );
        return error.UpdateClauseSilentlyAccepted;
    }
    // The pipeline logs its diagnostics; re-run the frontend directly so the
    // message itself can be asserted.
    const msgs = try frontendDiagnostics(alloc, source, file_name);
    for (msgs) |m| {
        if (std.mem.indexOf(u8, m, expected) != null) return;
    }
    std.debug.print("{s}: rejection must carry the shared cross-tier diagnostic, got: ", .{file_name});
    for (msgs) |m| std.debug.print("[{s}] ", .{m});
    std.debug.print("\n", .{});
    return error.WrongDiagnostic;
}

/// Parse + validate the source and return every diagnostic message. Each
/// parser module declares its own `ParseResult`, so the collection step is
/// duck-typed rather than a single expression.
fn collectDiagnostics(
    alloc: Allocator,
    parsed: anytype,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    for (parsed.errors) |e| try out.append(alloc, e);
    if (parsed.contract) |contract| {
        const val = try validate.validate(alloc, contract);
        for (val.errors) |e| try out.append(alloc, e.message);
    }
}

fn frontendDiagnostics(alloc: Allocator, source: []const u8, file_name: []const u8) ![]const []const u8 {
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    if (std.mem.endsWith(u8, file_name, ".runar.ts")) {
        try collectDiagnostics(alloc, parse_ts.parseTs(alloc, source, file_name), &out);
    } else if (std.mem.endsWith(u8, file_name, ".runar.zig")) {
        try collectDiagnostics(alloc, parse_zig.parseZig(alloc, source, file_name), &out);
    } else if (std.mem.endsWith(u8, file_name, ".runar.move")) {
        try collectDiagnostics(alloc, parse_move.parseMove(alloc, source, file_name), &out);
    } else if (std.mem.endsWith(u8, file_name, ".runar.java")) {
        try collectDiagnostics(alloc, parse_java.parseJava(alloc, source, file_name), &out);
    } else if (std.mem.endsWith(u8, file_name, ".runar.sol")) {
        try collectDiagnostics(alloc, parse_sol.parseSol(alloc, source, file_name), &out);
    } else {
        try collectDiagnostics(alloc, parse_go.parseGo(alloc, source, file_name), &out);
    }
    return out.items;
}

// ---------------------------------------------------------------------------
// The defect
// ---------------------------------------------------------------------------

test "N-061: a non-unit step is rejected, not coerced (.runar.zig)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try std.mem.replaceOwned(u8, alloc, src_zig, "i += 1", "i += 2");
    try expectRejectedWithSharedDiagnostic(alloc, src, "BoundedLoop.runar.zig");
}

// The Move surface has no update CLAUSE — the step is the last statement of
// the `while` body, and the induction variable, its start, the comparison
// direction and the step are one shape that either folds into a bounded loop
// or does not. So its rejection carries the Move shape diagnostic rather than
// the shared for-header update diagnostic. Both sentences say the same thing
// about the same program; this one names the whole shape because that is what
// the Move frontend matches on, and all seven tiers now emit it verbatim.
//
// This row used to assert the shared wording, which it got by accident: this
// tier reached the validator's update check because it trimmed `i = i + K`
// for any K. The other six folded `i = i + 2` into `i++` in the parser and
// silently ran the loop 5 times over i = 0..4 instead of 3 times over
// i = 0,2,4 — so "all seven reject a non-unit Move step" was never true.
test "N-061: a non-unit step is rejected, not coerced (.runar.move)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try std.mem.replaceOwned(u8, alloc, src_move, "i = i + 1;", "i = i + 2;");
    try expectRejectedWithDiagnostic(alloc, src, "BoundedLoop.runar.move", move_while_shape_diagnostic);
}

// A DESCENDING Move loop is a loop, not an error. The fold matched
// `i = i + …` only, so `i = i - 1` fell through to the unfolded stub and
// unrolled ZERO times — the body, and every assertion in it, silently absent
// from the script. Two independent facts are pinned here: it compiles, and it
// compiles to the same bytes as the equivalent TypeScript `for (let i = 5n;
// i > 1n; i--)`, which this tier already lowered correctly.
test "R-102: a descending Move while-fold compiles to the TS countdown bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var src = try std.mem.replaceOwned(u8, alloc, src_move, "let i: Int = 0;", "let i: Int = 5;");
    src = try std.mem.replaceOwned(u8, alloc, src, "while (i < 5) {", "while (i > 1) {");
    src = try std.mem.replaceOwned(u8, alloc, src, "i = i + 1;", "i = i - 1;");

    const move_hex = compileHex(alloc, src, "BoundedLoop.runar.move") orelse {
        std.debug.print("descending Move while-fold must compile\n", .{});
        return error.DescendingMoveLoopRejected;
    };

    var ts_src = try std.mem.replaceOwned(u8, alloc, src_ts, "let i: bigint = 0n", "let i: bigint = 5n");
    ts_src = try std.mem.replaceOwned(u8, alloc, ts_src, "i < 5;", "i > 1;");
    ts_src = try std.mem.replaceOwned(u8, alloc, ts_src, "i++", "i--");
    const ts_hex = compileHex(alloc, ts_src, "BoundedLoop.runar.ts") orelse {
        std.debug.print("the TS countdown control must compile\n", .{});
        return error.TsCountdownRejected;
    };

    try std.testing.expectEqualStrings(ts_hex, move_hex);
}

test "N-061: a non-unit step is rejected, not coerced (.runar.java)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try std.mem.replaceOwned(u8, alloc, src_java, "i.plus(Bigint.ONE)", "i.plus(Bigint.of(2))");
    try expectRejectedWithSharedDiagnostic(alloc, src, "BoundedLoop.runar.java");
}

test "N-061: a negative non-unit step is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var src = try std.mem.replaceOwned(u8, alloc, src_zig, "var i: i64 = 0;", "var i: i64 = 5;");
    src = try std.mem.replaceOwned(u8, alloc, src, "while (i < 5) : (i += 1)", "while (i > 0) : (i -= 2)");
    try expectRejectedWithSharedDiagnostic(alloc, src, "BoundedLoop.runar.zig");
}

/// A stateful contract parameterised on the for-loop update clause.
fn tsWithUpdate(alloc: Allocator, update: []const u8) ![]const u8 {
    return std.fmt.allocPrint(alloc,
        \\import {{ StatefulSmartContract, assert }} from 'runar-lang';
        \\
        \\class UpdateProbe extends StatefulSmartContract {{
        \\  count: bigint;
        \\
        \\  constructor(count: bigint) {{ super(count); this.count = count; }}
        \\
        \\  public unlock(expected: bigint): void {{
        \\    let acc: bigint = 0n;
        \\    for (let i: bigint = 0n; i < 3n; {s}) {{
        \\      acc = acc + i;
        \\    }}
        \\    assert(acc === expected);
        \\  }}
        \\}}
    , .{update});
}

test "N-061: an undefined function in the update position is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try tsWithUpdate(alloc, "undefinedFn()");
    try expectRejectedWithSharedDiagnostic(alloc, src, "UpdateProbe.runar.ts");
}

test "N-061: a state mutation in the update position is rejected, not dropped" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try tsWithUpdate(alloc, "this.count++");
    try expectRejectedWithSharedDiagnostic(alloc, src, "UpdateProbe.runar.ts");
}

test "N-061: an update advancing another variable is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try tsWithUpdate(alloc, "j++");
    try expectRejectedWithSharedDiagnostic(alloc, src, "UpdateProbe.runar.ts");
}

// ---------------------------------------------------------------------------
// Controls: every shape that compiles today must still compile, byte-identical
// ---------------------------------------------------------------------------

test "N-061 CONTROL: bounded-loop bytes unchanged on every surface with an update clause" {
    const cases = [_]struct { name: []const u8, src: []const u8, file: []const u8 }{
        .{ .name = "ts i++", .src = src_ts, .file = "BoundedLoop.runar.ts" },
        .{ .name = "sol i++", .src = src_sol, .file = "BoundedLoop.runar.sol" },
        .{ .name = "go i++", .src = src_go, .file = "BoundedLoop.runar.go" },
        .{ .name = "move while-fold", .src = src_move, .file = "BoundedLoop.runar.move" },
        .{ .name = "zig i += 1", .src = src_zig, .file = "BoundedLoop.runar.zig" },
        .{ .name = "java i = i.plus(ONE)", .src = src_java, .file = "BoundedLoop.runar.java" },
    };
    for (cases) |tc| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();
        const hex = compileHex(alloc, tc.src, tc.file) orelse {
            std.debug.print("{s}: must still compile\n", .{tc.name});
            return error.ControlRegressed;
        };
        std.testing.expectEqualStrings(bounded_loop_hex, hex) catch |e| {
            std.debug.print("{s}: bytes moved\n", .{tc.name});
            return e;
        };
    }
}

test "N-061 CONTROL: a countdown loop still compiles" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try tsWithUpdate(alloc, "i--");
    // Same shape, counting down: `i > 0n` with `i--`.
    const down = try std.mem.replaceOwned(u8, alloc, src, "i < 3n", "i > 0n");
    _ = compileHex(alloc, down, "UpdateProbe.runar.ts") orelse return error.CountdownRegressed;
}

// ---------------------------------------------------------------------------
// N-128: the .runar.java for-header update slot
// ---------------------------------------------------------------------------
//
// `parse_java.zig`'s parseForStmt recognised only `ident = expr`, `ident++`
// and `ident--` in the update slot. Anything else was skipped as raw tokens to
// the closing `)`, leaving `update == null`, and the Java header never set
// `header_requires_update` — so the validator read the C-style header as an
// implied-step surface and let it through. `count += Bigint.ONE`,
// `this.count += Bigint.ONE`, `this.count = this.count.plus(...)`, a bare
// `i.plus(Bigint.ONE)` call, an empty slot and, worst, `i += Bigint.TWO` (a
// non-unit step coerced to a unit step) all compiled in this tier alone.
//
// What these tests prove: each shape is refused with the shared cross-tier
// diagnostic, and the unit-step spellings TS accepts (`i++`, `++i`,
// `i += Bigint.ONE`, `i = i.plus(Bigint.ONE)`) still compile to the
// bounded-loop bytes. What they do not prove: anything about the other
// surfaces' headers, or that the refusal fires in the same pass as TS (TS
// refuses the empty slot in its parser; this tier refuses it in validate).

/// A stateful Java contract parameterised on the for-loop update clause.
fn javaWithUpdate(alloc: Allocator, update: []const u8) ![]const u8 {
    return std.fmt.allocPrint(alloc,
        \\package runar.examples.updateprobe;
        \\
        \\import runar.lang.StatefulSmartContract;
        \\import runar.lang.annotations.Public;
        \\import runar.lang.types.Bigint;
        \\
        \\class UpdateProbe extends StatefulSmartContract {{
        \\
        \\    Bigint count;
        \\
        \\    UpdateProbe(Bigint count) {{
        \\        super(count);
        \\        this.count = count;
        \\    }}
        \\
        \\    @Public
        \\    void increment() {{
        \\        for (Bigint i = Bigint.ZERO; i.lt(Bigint.TWO); {s}) {{ this.count = this.count.plus(Bigint.ONE); }}
        \\    }}
        \\}}
    , .{update});
}

test "N-128: unrepresentable .runar.java for-updates are rejected, not skipped" {
    const updates = [_][]const u8{
        "count += Bigint.ONE",
        "this.count += Bigint.ONE",
        "this.count = this.count.plus(Bigint.ONE)",
        "i += Bigint.TWO",
        "i.plus(Bigint.ONE)",
        "",
    };
    for (updates) |u| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();
        const src = try javaWithUpdate(alloc, u);
        expectRejectedWithSharedDiagnostic(alloc, src, "UpdateProbe.runar.java") catch |e| {
            std.debug.print("update `{s}`\n", .{u});
            return e;
        };
    }
}

// The recovery loop after the update also swallowed trailing tokens, so
// `i++, this.count++` compiled as `i++` with the state write dropped. TS
// refuses it in the parser with `expected ')', got ','`.
test "N-128: a comma-joined .runar.java for-update is rejected, not truncated" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try javaWithUpdate(alloc, "i++, this.count++");
    try expectRejectedWithDiagnostic(alloc, src, "UpdateProbe.runar.java", "expected ')', got ','");
}

test "N-128 CONTROL: unit-step .runar.java for-updates keep the bounded-loop bytes" {
    const updates = [_][]const u8{ "i++", "++i", "i += Bigint.ONE", "i = i.plus(Bigint.ONE)" };
    for (updates) |u| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();
        const src = try std.mem.replaceOwned(u8, alloc, src_java, "i = i.plus(Bigint.ONE)", u);
        const hex = compileHex(alloc, src, "BoundedLoop.runar.java") orelse {
            std.debug.print("update `{s}`: must still compile\n", .{u});
            return error.ControlRegressed;
        };
        std.testing.expectEqualStrings(bounded_loop_hex, hex) catch |e| {
            std.debug.print("update `{s}`: bytes moved\n", .{u});
            return e;
        };
    }
}

// ---------------------------------------------------------------------------
// N-132: an EMPTY update slot on the C-style .runar.ts / .runar.sol headers
// ---------------------------------------------------------------------------
//
// `for (let i = 0n; i < 3n; )` never advances `i` in the source, yet both
// parsers left `update == null` without setting `header_requires_update`, so
// validate.zig read the C-style header as an implied-step surface and the
// unrolled loop advanced `i` anyway (byte-identical to `i++`). The TS reference
// refuses both shapes in its parsers: `.runar.ts` with "For loop must have an
// update expression", `.runar.sol` with "Unexpected token in expression: ')'"
// (its Solidity parser always parses an update expression).
//
// What these tests prove: each parser refuses the empty slot with the
// reference's text. What they do not prove: anything about the other surfaces
// (pinned by the conformance negatives N180/N181 across all seven tiers).

test "N-132: an empty .runar.ts for-update is rejected with the reference diagnostic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try tsWithUpdate(alloc, "");
    try expectRejectedWithDiagnostic(alloc, src, "UpdateProbe.runar.ts", "For loop must have an update expression");
}

test "N-132: an empty .runar.sol for-update is rejected with the reference diagnostic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try std.mem.replaceOwned(u8, alloc, src_sol, "i < 5; i++)", "i < 5; )");
    try expectRejectedWithDiagnostic(alloc, src, "BoundedLoop.runar.sol", "Unexpected token in expression: ')'");
}

// ---------------------------------------------------------------------------
// N-116: an update that reads the iterator (or is a literal) without advancing it
// ---------------------------------------------------------------------------
//
// The validator accepted a bare identifier / literal update as the "no-op
// sentinel" the while-shaped parsers synthesize, and the step was then inferred
// from the comparison direction -- so `var i = 3; while (i < 5) : (i)`, a source
// loop that never terminates, unrolled to two laps over i = 3, 4 in six tiers.
// This tier refused the `.runar.zig` spelling only by accident: its parser
// dropped a bare continue expression, so nothing folded and the condition rule
// fired instead of the update rule.
//
// What these tests prove: the `.runar.zig` continue expression and the
// `.runar.ts` for-update are refused with the shared R-065 sentence. What they
// do not prove: anything about while loops whose update lives in the body
// (those keep a placeholder iterator and the condition rule refuses them).

test "N-116: a .runar.zig continue expression that only reads the iterator is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    var src = try std.mem.replaceOwned(u8, alloc, src_zig, "var i: i64 = 0;", "var i: i64 = 3;");
    src = try std.mem.replaceOwned(u8, alloc, src, "while (i < 5) : (i += 1)", "while (i < 5) : (i)");
    try expectRejectedWithSharedDiagnostic(alloc, src, "BoundedLoop.runar.zig");
}

test "N-116: a .runar.ts for-update that only reads the iterator is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    try expectRejectedWithSharedDiagnostic(alloc, try tsWithUpdate(alloc, "i"), "UpdateProbe.runar.ts");
}

test "N-116: a .runar.ts literal for-update is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    try expectRejectedWithSharedDiagnostic(alloc, try tsWithUpdate(alloc, "0n"), "UpdateProbe.runar.ts");
}

// ---------------------------------------------------------------------------
// N-135: an EMPTY condition slot on the C-style .runar.ts header
// ---------------------------------------------------------------------------
//
// `for (let i = 0n; ; i++)` has no exit test in the source. The TS reference
// refuses it in its parser with "For loop must have a condition". This parser
// ran `skipSemicolons()` after the initializer, which ate BOTH `;`s: the bare
// empty condition was refused only by accident (`i++` misparsed as the
// condition, then "For loop must have an update expression"), and the shifted
// header `for (let i = 0n;; i < 3n; i++)` - not valid TypeScript - compiled
// exactly like `for (let i = 0n; i < 3n; i++)`.
//
// What these tests prove: the .runar.ts parser refuses both shapes with the
// reference's condition diagnostic. What they do not prove: other surfaces or
// tiers (pinned by the conformance negatives N274/N275).

test "N-135: an empty .runar.ts for-condition is rejected with the reference diagnostic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const base = try tsWithUpdate(alloc, "i++");
    const src = try std.mem.replaceOwned(u8, alloc, base, "0n; i < 3n; i++)", "0n; ; i++)");
    try expectRejectedWithDiagnostic(alloc, src, "UpdateProbe.runar.ts", "For loop must have a condition");
}

test "N-135: a shifted .runar.ts for-header (;; cond; update) is rejected with the reference diagnostic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const base = try tsWithUpdate(alloc, "i++");
    const src = try std.mem.replaceOwned(u8, alloc, base, "0n; i < 3n; i++)", "0n;; i < 3n; i++)");
    try expectRejectedWithDiagnostic(alloc, src, "UpdateProbe.runar.ts", "For loop must have a condition");
}

// ---------------------------------------------------------------------------
// N-306: a non-declaration for-initializer on the C-style .runar.ts header
// ---------------------------------------------------------------------------
//
// `for (i = 0n; _i < 3n; _i++)` has no `let`/`const` in the initializer slot.
// The TS reference refuses it in its parser with "For loop must have a
// variable declaration initializer". This parser's non-`let`/`const` branch
// (the `else` in `parseForStmt`) instead just skips tokens to the next `;`,
// leaving `var_name` at its synthetic default `_i` with no diagnostic at
// all. That substitution is invisible when the condition/update still
// reference the original name `i`, because `cond_tests_iter` then compares
// `i` against the default `_i`, mismatches, and the validator's "condition
// must compare the loop variable" rule refuses the program anyway, for an
// unrelated reason. Writing the condition/update against the substituted
// name `_i` instead -- exactly what a developer who noticed the generated
// variable would do -- makes `cond_tests_iter` true and the garbage
// initializer compiles clean.
//
// What this test proves: the .runar.ts parser refuses a non-declaration
// for-initializer with the reference's diagnostic, even when the rest of the
// header is written against the substituted name. What it does not prove:
// other surfaces or tiers (pinned by the conformance negatives N277-N279).

/// A stateful contract parameterised on the for-loop HEADER, with a body
/// that never references the loop variable by name -- unlike
/// `tsWithUpdate`'s body (`acc = acc + i`), so a substituted `_i = 0`
/// iterator can't be caught by an accidental "condition must compare the
/// loop variable" validation error instead of the parser's own diagnostic.
fn tsForInitializer(alloc: Allocator, init: []const u8) ![]const u8 {
    return std.fmt.allocPrint(alloc,
        \\import {{ StatefulSmartContract, assert }} from 'runar-lang';
        \\
        \\class InitProbe extends StatefulSmartContract {{
        \\  count: bigint;
        \\
        \\  constructor(count: bigint) {{ super(count); this.count = count; }}
        \\
        \\  public unlock(expected: bigint): void {{
        \\    let acc: bigint = 0n;
        \\    for ({s}; _i < 3n; _i++) {{
        \\      acc = acc + 1n;
        \\    }}
        \\    assert(acc === expected);
        \\  }}
        \\}}
    , .{init});
}

test "N-306: a non-declaration .runar.ts for-initializer is rejected with the reference diagnostic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try tsForInitializer(alloc, "i = 0n");
    try expectRejectedWithDiagnostic(
        alloc,
        src,
        "InitProbe.runar.ts",
        "For loop must have a variable declaration initializer",
    );
}

// Control: a well-formed `let` initializer must keep compiling clean -- the
// fix narrows only the non-declaration branch of the initializer dispatch.
test "N-306: a let .runar.ts for-initializer still compiles clean" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try tsForInitializer(alloc, "let _i: bigint = 0n");
    if (compileHex(alloc, src, "InitProbe.runar.ts") == null) {
        std.debug.print("a `let` for-initializer must still compile\n", .{});
        return error.LetInitializerRejected;
    }
}
