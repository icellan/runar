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
        if (std.mem.indexOf(u8, m, loop_update_diagnostic) != null) return;
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

test "N-061: a non-unit step is rejected, not coerced (.runar.move)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const src = try std.mem.replaceOwned(u8, alloc, src_move, "i = i + 1;", "i = i + 2;");
    try expectRejectedWithSharedDiagnostic(alloc, src, "BoundedLoop.runar.move");
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
