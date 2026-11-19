//! A statement-position `++` / `--` on an element of a NESTED FixedArray
//! (`this.grid[0][1]++`).
//!
//! The N-124 desugar only matched a single-level chain: it asked whether the
//! increment's immediate object (`this.grid[0]`) was an array property, which
//! it is not, so the increment fell through to the expression-position refusal
//! ("only supported as a statement") even though it IS a statement. Go, and the
//! other tiers, compile it to exactly the hand-written assignment, which Zig
//! already accepts. This pins that the increment compiles to the bytes of the
//! assignment it is defined to be.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

fn src(comptime body: []const u8) []const u8 {
    return
    \\import { StatefulSmartContract, FixedArray } from 'runar-lang';
    \\class Grid extends StatefulSmartContract {
    \\  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];
    \\  constructor() { super(); }
    \\  public bump() {
    \\
    ++ "    " ++ body ++ "\n" ++
        \\  }
        \\}
    ;
}

fn compileHex(a: std.mem.Allocator, source: []const u8) ![]const u8 {
    const result = try compiler_api.compileSource(a, source, "Grid.runar.ts");
    if (result.artifact_json) |j| a.free(j);
    for (result.warnings) |line| a.free(line);
    a.free(result.warnings);
    return result.script_hex;
}

test "nested FixedArray: `this.grid[0][1]++` compiles to `this.grid[0][1] = this.grid[0][1] + 1n`" {
    const a = std.testing.allocator;
    const incr = try compileHex(a, src("this.grid[0][1]++;"));
    defer a.free(incr);
    const hand = try compileHex(a, src("this.grid[0][1] = this.grid[0][1] + 1n;"));
    defer a.free(hand);
    try std.testing.expectEqualStrings(hand, incr);
}

test "nested FixedArray: `this.grid[1][0]--` compiles to `this.grid[1][0] = this.grid[1][0] - 1n`" {
    const a = std.testing.allocator;
    const decr = try compileHex(a, src("this.grid[1][0]--;"));
    defer a.free(decr);
    const hand = try compileHex(a, src("this.grid[1][0] = this.grid[1][0] - 1n;"));
    defer a.free(hand);
    try std.testing.expectEqualStrings(hand, decr);
}
