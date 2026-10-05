//! N-153 — statement shapes on the .sol / .move / .go / .rs surfaces, aligned
//! to the TS reference (port of the Zig rows of
//! conformance/negatives/n153-statement-shape-parity.test.ts).
//!
//! Pre-fix the Zig tier alone:
//!   - skipped an empty statement `;` on .runar.rs and .runar.sol (TS refuses
//!     both with "Unexpected token in expression: ';'");
//!   - compiled .runar.move `abort 0;` as assert(false) (TS refuses `abort`:
//!     "Undefined variable 'abort'");
//!   - dropped .runar.go `_ = y` when `y` was a bare name, so
//!     `y := c.check(x); _ = y` compiled to 76009d5177 where TS binds `_`
//!     and emits 76009d76517777.
//!
//! Proves: in the Zig tier, each refused shape is refused with the TS
//! diagnostic and each accepted shape compiles to the TS bytes in both
//! constant-folding modes.
//! Does NOT prove: the other six tiers (the conformance test does), or
//! on-chain behaviour.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const SOL_HEAD =
    \\pragma runar ^0.1.0;
    \\
    \\contract Disc is SmartContract {
    \\    bigint immutable t;
    \\
    \\    constructor(bigint _t) {
    \\        t = _t;
    \\    }
    \\
    \\    function unlock(bigint x) public {
    \\
;
const SOL_TAIL =
    \\
    \\        require(true);
    \\    }
    \\}
    \\
;

const MOVE_HEAD =
    \\module Disc {
    \\    use runar::SmartContract;
    \\    use runar::types::{Int};
    \\
    \\    struct Disc {
    \\        t: Int,
    \\    }
    \\
    \\    public fun unlock(contract: &Disc, x: Int) {
    \\
;
const MOVE_TAIL =
    \\
    \\        assert!(true, 0);
    \\    }
    \\}
    \\
;

const RS_HEAD =
    \\use runar::prelude::*;
    \\
    \\#[runar::contract]
    \\pub struct Disc {
    \\    #[readonly]
    \\    pub t: Bigint,
    \\}
    \\
    \\impl Disc {
    \\    pub fn unlock(&self, x: Bigint) {
    \\
;
const RS_TAIL =
    \\
    \\        assert!(true);
    \\    }
    \\}
    \\
;

const GO_HEAD =
    \\package contract
    \\
    \\import runar "github.com/icellan/runar/packages/runar-go"
    \\
    \\type Disc struct {
    \\    runar.SmartContract
    \\    T runar.Bigint `runar:"readonly"`
    \\}
    \\
    \\func (c *Disc) Unlock(x runar.Bigint) {
    \\
;
const GO_TAIL =
    \\
    \\    runar.Assert(true)
    \\}
    \\
    \\func (c *Disc) check(x runar.Bigint) runar.Bigint {
    \\    runar.Assert(x == c.T)
    \\    return x
    \\}
    \\
;

fn expectRefused(comptime head: []const u8, comptime stmt: []const u8, comptime tail: []const u8, file: []const u8, want: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diag: compiler_api.Diagnostics = .{};
    if (compiler_api.runPipeline(arena.allocator(), head ++ stmt ++ tail, file, .{ .disable_constant_folding = true }, &diag)) |_| {
        std.debug.print("{s} `{s}` compiled, expected a refusal\n", .{ file, stmt });
        return error.ShapeCompiled;
    } else |_| {}
    for (diag.errors.items) |line| {
        if (std.mem.indexOf(u8, line, want) != null) return;
    }
    std.debug.print("{s} `{s}`: want \"{s}\", got:\n", .{ file, stmt, want });
    for (diag.errors.items) |line| std.debug.print("    {s}\n", .{line});
    return error.WrongDiagnostic;
}

fn expectHex(comptime stmt: []const u8, want: []const u8) !void {
    for ([_]bool{ false, true }) |fold_off| {
        const r = try compiler_api.compileSourceWithOptions(std.testing.allocator, GO_HEAD ++ stmt ++ GO_TAIL, "Disc.runar.go", fold_off);
        defer std.testing.allocator.free(r.script_hex);
        defer if (r.artifact_json) |j| std.testing.allocator.free(j);
        std.testing.expectEqualStrings(want, r.script_hex) catch |e| {
            std.debug.print("go `{s}` (fold-off={}) diverged from the TS bytes\n", .{ stmt, fold_off });
            return e;
        };
    }
}

test "N-153: .runar.rs `;` is refused with the TS diagnostic" {
    try expectRefused(RS_HEAD, "        ;", RS_TAIL, "Disc.runar.rs", "Unexpected token in expression: ';'");
    try expectRefused(RS_HEAD, "        assert!(x == self.t);;", RS_TAIL, "Disc.runar.rs", "Unexpected token in expression: ';'");
}

test "N-153: .runar.sol `;` is refused with the TS diagnostic" {
    try expectRefused(SOL_HEAD, "        ;", SOL_TAIL, "Disc.runar.sol", "Unexpected token in expression: ';'");
    try expectRefused(SOL_HEAD, "        require(x == t);;", SOL_TAIL, "Disc.runar.sol", "Unexpected token in expression: ';'");
}

test "N-153: .runar.move `abort` is refused with the TS diagnostic" {
    try expectRefused(MOVE_HEAD, "        abort 0;", MOVE_TAIL, "Disc.runar.move", "Undefined variable 'abort'");
    try expectRefused(MOVE_HEAD, "        if (x != contract.t) { abort 0; };", MOVE_TAIL, "Disc.runar.move", "Undefined variable 'abort'");
}

test "N-153: .runar.go `_ = <local>` binds `_` like the TS reference" {
    try expectHex("\ty := c.check(x)\n\t_ = y", "76009d76517777");
    try expectHex("\ty := x + 1\n\t_ = y\n\t_ = y", "8b767c517777");
}

test "N-153 control: the shapes TS accepts still compile to the TS bytes" {
    try expectHex("\t_ = x", "5177");
    try expectHex("\t_ = c.T", "00517777");
    try expectHex("\t_ = c.check(x)", "76009d5177");
}
