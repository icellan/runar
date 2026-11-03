//! F-222 — an affine value consumed once in each of two mutually exclusive
//! if/else arms.
//!
//! The then and else arms never both run, so `checkSig(sig, pk)` once per arm
//! consumes `sig` once on every path. The checker walked both arms against one
//! shared consumed set and refused the else-arm use as a double consumption.
//!
//! Proves: the type checker's verdict for one consumption per arm (direct,
//! through an alias, nested ifs), and that every shape where some path consumes
//! twice is still refused: an arm plus after the if (then, else, both, nested,
//! via an alias), before plus an arm, twice in one arm, and once per arm inside
//! a 2-iteration loop. Does not prove: the ternary form, which is not an if
//! statement and is still refused, nor anything about the emitted script.

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const typecheck = @import("../passes/typecheck.zig");

const DOUBLE = "affine value 'sig' has already been consumed";

const Case = struct { body: []const u8, want: ?[]const u8 };

const cases = [_]Case{
    .{ .body = "if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); }", .want = null },
    .{ .body = "if (flag) { const a: Sig = sig; assert(checkSig(a, this.pk)); } else { assert(checkSig(sig, this.pk)); }", .want = null },
    .{ .body = "if (flag) { assert(checkSig(sig, this.pk)); } else { if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } }", .want = null },
    .{ .body = "if (flag) { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));", .want = DOUBLE },
    .{ .body = "if (flag) { assert(true); } else { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));", .want = DOUBLE },
    .{ .body = "if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));", .want = DOUBLE },
    .{ .body = "if (flag) { if (flag) { assert(checkSig(sig, this.pk)); } } else { assert(true); } assert(checkSig(sig, this.pk));", .want = DOUBLE },
    .{ .body = "const a: Sig = sig; if (flag) { assert(checkSig(a, this.pk)); } else { assert(true); } assert(checkSig(sig, this.pk));", .want = DOUBLE },
    .{ .body = "assert(checkSig(sig, this.pk)); if (flag) { assert(checkSig(sig, this.pk)); }", .want = DOUBLE },
    .{ .body = "if (flag) { assert(checkSig(sig, this.pk)); assert(checkSig(sig, this.pk)); } else { assert(true); }", .want = DOUBLE },
    .{ .body = "if (flag) { assert(true); } else { assert(checkSig(sig, this.pk)); assert(checkSig(sig, this.pk)); }", .want = DOUBLE },
    .{ .body = "for (let i = 0n; i < 2n; i++) { if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } }", .want = DOUBLE },
};

test "F-222: affine consumption across mutually exclusive if/else arms" {
    for (cases) |c| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const w = arena.allocator();
        const src = try std.fmt.allocPrint(w,
            \\class C extends SmartContract {{
            \\  readonly pk: PubKey;
            \\  constructor(pk: PubKey) {{ super(pk); this.pk = pk; }}
            \\  public m(sig: Sig, flag: boolean) {{
            \\    {s}
            \\    assert(true);
            \\  }}
            \\}}
        , .{c.body});
        const parsed = parse_ts.parseTs(w, src, "F222.runar.ts");
        if (parsed.errors.len > 0) {
            for (parsed.errors) |e| std.debug.print("  unexpected parse error: {s}\n", .{e});
            return error.TestFixtureDidNotParse;
        }
        const result = try typecheck.typeCheck(w, parsed.contract orelse return error.TestFixtureDidNotParse);
        if (c.want) |needle| {
            var found = false;
            for (result.errors) |msg| {
                if (std.mem.indexOf(u8, msg, needle) != null) found = true;
            }
            if (!found) {
                std.debug.print("  F-222 double consumption not refused: {s} (errors: {d})\n", .{ c.body, result.errors.len });
                return error.AffineDoubleConsumptionAccepted;
            }
        } else if (result.errors.len != 0) {
            for (result.errors) |msg| std.debug.print("  F-222 unexpected error in {s}: {s}\n", .{ c.body, msg });
            return error.MutuallyExclusiveArmsRefused;
        }
    }
}
