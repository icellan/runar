//! F-025 (CL-BUG-060 / CL-BUG-106) — a for-loop bound that is not an integer
//! literal silently became a ZERO-iteration loop on seven of the nine surfaces.
//!
//! This tier's `ForStmt` does not keep the bound expression. Each surface
//! parser collapses it to an `i64` (default 0), assigning it only inside a
//! `.literal_int` arm, and `ForStmt.bound_is_const` exists so the validator can
//! refuse the loop when that collapse lost information. Only `parse_ts` and
//! `parse_move` ever set it; the field defaulted to `true`, so on `.sol`, `.go`,
//! `.rs`, `.py`, `.zig`, `.rb` and `.java`
//!
//!     for (i = 0; i < this.n; i++) { sum = sum + i + 10; }
//!
//! compiled to a locking script with the loop body gone (`007b9c77`: `sum = 0`
//! then the final compare). Under `@bsv/sdk` `Spend.validate()` that script
//! ACCEPTS `x = 0` and REJECTS `x = 33` — the opposite of the source at n = 3.
//!
//! The same collapse hit a NEGATIVE literal bound (`i > -2`), which the
//! parsers never recognised as a literal: it unrolled from a bound of 0 —
//! fewer iterations than the source, and different bytes from the reference.
//!
//! The reference (TypeScript) tier, run on every row of this matrix:
//!   * `this.<prop>` bound  -> refused by pass 2 with `RUNTIME_BOUND`
//!   * identifier bound     -> passes pass 2 (`isCompileTimeConstant` trusts an
//!     identifier), then refused by ANF lowering with `IDENT_BOUND`
//!   * literal bound, including a negated literal -> compiles
//! It is the same on all nine surfaces, and this file pins the Zig tier to it.
//!
//! What this proves: on every surface, each of the three non-literal bound
//! shapes is REFUSED with the reference's sentence (not the other one), and
//! the literal and negated-literal shapes compile to the reference's bytes.
//! What it does NOT prove: anything about the other six tiers, or about bound
//! shapes outside this matrix (e.g. `N > i` with the operands reversed, or a
//! bound expression such as `3 + 1`, which the reference also refuses).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const RUNTIME_BOUND = "For loop bound must be a compile-time constant (literal or const variable)";
const IDENT_BOUND = "Cannot determine loop bound at compile time. For-loop bounds must be integer literals.";

const Surface = struct {
    ext: []const u8,
    template: []const u8,
    /// Loop headers per shape; `@LOCAL@` in the template becomes `local`
    /// for the `local` shape and empty otherwise.
    rt: []const u8,
    param: []const u8,
    local_hdr: []const u8,
    lit: []const u8,
    neg: []const u8,
    local: []const u8,
    step: []const u8 = "",
    neg_step: []const u8 = "",
    /// Reference (TS tier, fold-off) hex of the negated-literal shape.
    neg_hex: []const u8 = "011e7b9c77",
};

const surfaces = [_]Surface{
    .{
        .ext = "ts",
        .template =
        \\import { SmartContract, assert } from 'runar-lang';
        \\
        \\class Probe extends SmartContract {
        \\  readonly n: bigint;
        \\
        \\  constructor(n: bigint) {
        \\    super(n);
        \\    this.n = n;
        \\  }
        \\
        \\  public verify(x: bigint, k: bigint): void {
        \\    let sum: bigint = 0n;
        \\@LOCAL@    @HEADER@ {
        \\      sum = sum + i + 10n;
        \\    }
        \\    assert(sum === x);
        \\  }
        \\}
        \\
        ,
        .rt = "for (let i: bigint = 0n; i < this.n; i++)",
        .param = "for (let i: bigint = 0n; i < k; i++)",
        .local_hdr = "for (let i: bigint = 0n; i < lim; i++)",
        .lit = "for (let i: bigint = 0n; i < 3n; i++)",
        .neg = "for (let i: bigint = 1n; i > -2n; i--)",
        .local = "    const lim: bigint = 3n;\n",
    },
    .{
        .ext = "sol",
        .template =
        \\pragma runar ^0.1.0;
        \\
        \\contract Probe is SmartContract {
        \\    int immutable n;
        \\
        \\    constructor(int _n) {
        \\        n = _n;
        \\    }
        \\
        \\    function verify(int x, int k) public {
        \\        int sum = 0;
        \\@LOCAL@        @HEADER@ {
        \\            sum = sum + i + 10;
        \\        }
        \\        require(sum == x);
        \\    }
        \\}
        \\
        ,
        // Solidity reads state without `this.`: the bare `n` is a property.
        .rt = "for (int i = 0; i < n; i++)",
        .param = "for (int i = 0; i < k; i++)",
        .local_hdr = "for (int i = 0; i < lim; i++)",
        .lit = "for (int i = 0; i < 3; i++)",
        .neg = "for (int i = 1; i > -2; i--)",
        .local = "        int lim = 3;\n",
    },
    .{
        .ext = "move",
        .template =
        \\module Probe {
        \\    use runar::types::{Int};
        \\
        \\    struct Probe {
        \\        n: Int,
        \\    }
        \\
        \\    public fun verify(contract: &Probe, x: Int, k: Int) {
        \\        let sum: Int = 0;
        \\@LOCAL@        @HEADER@ {
        \\            sum = sum + i + 10;
        \\            @STEP@
        \\        };
        \\        assert_eq!(sum, x);
        \\    }
        \\}
        \\
        ,
        .rt = "let i: Int = 0;\n        while (i < contract.n)",
        .param = "let i: Int = 0;\n        while (i < k)",
        .local_hdr = "let i: Int = 0;\n        while (i < lim)",
        .lit = "let i: Int = 0;\n        while (i < 3)",
        .neg = "let i: Int = 1;\n        while (i > -2)",
        .local = "        let lim: Int = 3;\n",
        .step = "i = i + 1;",
        .neg_step = "i = i - 1;",
    },
    .{
        .ext = "go",
        .template =
        \\package contract
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Probe struct {
        \\    runar.SmartContract
        \\    N runar.Int `runar:"readonly"`
        \\}
        \\
        \\func (c *Probe) Verify(x runar.Int, k runar.Int) {
        \\    sum := runar.Int(0)
        \\@LOCAL@    @HEADER@ {
        \\        sum = sum + i + 10
        \\    }
        \\    runar.Assert(sum == x)
        \\}
        \\
        ,
        .rt = "for i := runar.Int(0); i < c.N; i++",
        .param = "for i := runar.Int(0); i < k; i++",
        .local_hdr = "for i := runar.Int(0); i < lim; i++",
        .lit = "for i := runar.Int(0); i < 3; i++",
        .neg = "for i := runar.Int(1); i > -2; i--",
        .local = "    lim := runar.Int(3)\n",
    },
    .{
        .ext = "rs",
        .template =
        \\use runar::prelude::*;
        \\
        \\#[runar::contract]
        \\struct Probe {
        \\    #[readonly]
        \\    n: Int,
        \\}
        \\
        \\impl Probe {
        \\    pub fn verify(&self, x: Int, k: Int) {
        \\        let mut sum: Int = 0;
        \\@LOCAL@        @HEADER@ {
        \\            sum = sum + i + 10;
        \\        }
        \\        assert!(sum == x);
        \\    }
        \\}
        \\
        ,
        .rt = "for i in 0..self.n",
        .param = "for i in 0..k",
        .local_hdr = "for i in 0..lim",
        .lit = "for i in 0..3",
        // (-2..2).rev() is 1, 0, -1, -2: four laps, 1 + 0 - 1 - 2 + 40 = 38.
        .neg = "for i in (-2..2).rev()",
        .local = "        let lim: Int = 3;\n",
        .neg_hex = "01267b9c77",
    },
    .{
        .ext = "py",
        .template =
        \\from runar import SmartContract, Bigint, public, assert_
        \\
        \\class Probe(SmartContract):
        \\    n: Bigint
        \\
        \\    def __init__(self, n: Bigint):
        \\        super().__init__(n)
        \\        self.n = n
        \\
        \\    @public
        \\    def verify(self, x: Bigint, k: Bigint):
        \\        sum_: Bigint = 0
        \\@LOCAL@        @HEADER@:
        \\            sum_ = sum_ + i + 10
        \\        assert_(sum_ == x)
        \\
        ,
        .rt = "for i in range(self.n)",
        .param = "for i in range(k)",
        .local_hdr = "for i in range(lim)",
        .lit = "for i in range(3)",
        .neg = "for i in range(1, -2, -1)",
        .local = "        lim: Bigint = 3\n",
    },
    .{
        .ext = "zig",
        .template =
        \\const runar = @import("runar");
        \\
        \\pub const Probe = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    n: i64,
        \\
        \\    pub fn init(n: i64) Probe {
        \\        return .{ .n = n };
        \\    }
        \\
        \\    pub fn verify(self: *const Probe, x: i64, k: i64) void {
        \\        var sum: i64 = 0;
        \\@LOCAL@        @HEADER@ {
        \\            sum = sum + i + 10;
        \\        }
        \\        runar.assert(sum == x);
        \\    }
        \\};
        \\
        ,
        .rt = "var i: i64 = 0;\n        while (i < self.n) : (i += 1)",
        .param = "var i: i64 = 0;\n        while (i < k) : (i += 1)",
        .local_hdr = "var i: i64 = 0;\n        while (i < lim) : (i += 1)",
        .lit = "var i: i64 = 0;\n        while (i < 3) : (i += 1)",
        .neg = "var i: i64 = 1;\n        while (i > -2) : (i -= 1)",
        .local = "        const lim: i64 = 3;\n",
    },
    .{
        .ext = "rb",
        .template =
        \\require 'runar'
        \\
        \\class Probe < Runar::SmartContract
        \\  prop :n, Bigint
        \\
        \\  def initialize(n)
        \\    super(n)
        \\    @n = n
        \\  end
        \\
        \\  runar_public x: Bigint, k: Bigint
        \\  def verify(x, k)
        \\    sum = 0
        \\@LOCAL@    @HEADER@
        \\      sum = sum + i + 10
        \\    end
        \\    assert sum == x
        \\  end
        \\end
        \\
        ,
        .rt = "for i in 0...@n",
        .param = "for i in 0...k",
        .local_hdr = "for i in 0...lim",
        .lit = "for i in 0...3",
        // 1.downto(-2) is 1, 0, -1, -2: four laps, 38.
        .neg = "for i in 1.downto(-2)",
        .local = "    lim = 3\n",
        .neg_hex = "01267b9c77",
    },
    .{
        .ext = "java",
        .template =
        \\package runar.examples.probe;
        \\
        \\import runar.lang.SmartContract;
        \\import runar.lang.annotations.Public;
        \\import runar.lang.annotations.Readonly;
        \\import runar.lang.types.Bigint;
        \\
        \\import static runar.lang.Builtins.assertThat;
        \\
        \\class Probe extends SmartContract {
        \\
        \\    @Readonly Bigint n;
        \\
        \\    Probe(Bigint n) {
        \\        super(n);
        \\        this.n = n;
        \\    }
        \\
        \\    @Public
        \\    void verify(Bigint x, Bigint k) {
        \\        Bigint sum = Bigint.ZERO;
        \\@LOCAL@        @HEADER@ {
        \\            sum = sum.plus(i).plus(Bigint.of(10));
        \\        }
        \\        assertThat(sum.eq(x));
        \\    }
        \\}
        \\
        ,
        .rt = "for (Bigint i = Bigint.ZERO; i.lt(this.n); i = i.plus(Bigint.ONE))",
        .param = "for (Bigint i = Bigint.ZERO; i.lt(k); i = i.plus(Bigint.ONE))",
        .local_hdr = "for (Bigint i = Bigint.ZERO; i.lt(lim); i = i.plus(Bigint.ONE))",
        .lit = "for (Bigint i = Bigint.ZERO; i.lt(Bigint.of(3)); i = i.plus(Bigint.ONE))",
        .neg = "for (Bigint i = Bigint.ONE; i.gt(Bigint.of(-2)); i = i.minus(Bigint.ONE))",
        .local = "        Bigint lim = Bigint.of(3);\n",
    },
};

const Shape = enum { rt, param, local, lit, neg };

fn render(a: std.mem.Allocator, s: Surface, shape: Shape) ![]const u8 {
    const header = switch (shape) {
        .rt => s.rt,
        .param => s.param,
        .local => s.local_hdr,
        .lit => s.lit,
        .neg => s.neg,
    };
    const a1 = try std.mem.replaceOwned(u8, a, s.template, "@LOCAL@", if (shape == .local) s.local else "");
    const a2 = try std.mem.replaceOwned(u8, a, a1, "@HEADER@", header);
    return std.mem.replaceOwned(u8, a, a2, "@STEP@", if (shape == .neg) s.neg_step else s.step);
}

fn fileName(a: std.mem.Allocator, s: Surface) ![]const u8 {
    return std.fmt.allocPrint(a, "Probe.runar.{s}", .{s.ext});
}

/// The loop must be refused, and one of the refusal lines must carry
/// `expected` while none carries `other` (the reference emits exactly one).
fn expectRefused(s: Surface, shape: Shape, expected: []const u8, other: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src = try render(a, s, shape);
    var diag: compiler_api.Diagnostics = .{};
    if (compiler_api.runPipeline(a, src, try fileName(a, s), .{ .disable_constant_folding = true }, &diag)) |_| {
        std.debug.print(".runar.{s} {s}: a non-literal loop bound compiled (body unrolled 0 times)\n", .{ s.ext, @tagName(shape) });
        return error.NonLiteralLoopBoundCompiled;
    } else |_| {}
    var found = false;
    var has_other = false;
    for (diag.errors.items) |line| {
        if (std.mem.indexOf(u8, line, expected) != null) found = true;
        if (std.mem.indexOf(u8, line, other) != null) has_other = true;
    }
    if (!found or has_other) {
        std.debug.print(".runar.{s} {s}: expected the reference diagnostic \"{s}\", got:\n", .{ s.ext, @tagName(shape), expected });
        for (diag.errors.items) |line| std.debug.print("    {s}\n", .{line});
        return error.WrongDiagnostic;
    }
}

fn expectHex(s: Surface, shape: Shape, expected: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src = try render(a, s, shape);
    var diag: compiler_api.Diagnostics = .{};
    _ = compiler_api.runPipeline(a, src, try fileName(a, s), .{ .disable_constant_folding = true }, &diag) catch |err| {
        std.debug.print(".runar.{s} {s}: must compile, got {s}:\n", .{ s.ext, @tagName(shape), @errorName(err) });
        for (diag.errors.items) |line| std.debug.print("    {s}\n", .{line});
        return err;
    };
    const result = try compiler_api.compileSourceWithOptions(a, src, try fileName(a, s), true);
    if (!std.mem.eql(u8, expected, result.script_hex)) {
        std.debug.print(".runar.{s} {s}: expected reference hex {s}, got {s}\n", .{ s.ext, @tagName(shape), expected, result.script_hex });
        return error.HexMismatch;
    }
}

test "F-025: a runtime (this.<prop>) loop bound is refused on all nine surfaces" {
    for (surfaces) |s| try expectRefused(s, .rt, RUNTIME_BOUND, IDENT_BOUND);
}

test "F-025: a parameter loop bound is refused on all nine surfaces" {
    for (surfaces) |s| try expectRefused(s, .param, IDENT_BOUND, RUNTIME_BOUND);
}

test "F-025: a local-variable loop bound is refused on all nine surfaces" {
    for (surfaces) |s| try expectRefused(s, .local, IDENT_BOUND, RUNTIME_BOUND);
}

// Controls: the fail-closed default must not refuse a real literal bound, and
// the bytes are the reference tier's (`10 + 11 + 12 = 33`, folded to one push).
test "F-025: a literal loop bound compiles to the reference bytes on all nine surfaces" {
    for (surfaces) |s| try expectHex(s, .lit, "01217b9c77");
}

test "F-025: a negated-literal loop bound compiles to the reference bytes on all nine surfaces" {
    for (surfaces) |s| try expectHex(s, .neg, s.neg_hex);
}
