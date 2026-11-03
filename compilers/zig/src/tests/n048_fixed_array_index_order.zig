//! N-048 (external "PrematurePeek"): pass 3b hoists a computed FixedArray
//! index to `const __idx_K` in front of its whole statement. In
//!
//!     assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);
//!
//! that bound the index BEFORE the increment, so the gate read the
//! pre-increment slot (an outsider spend at cursor 0 was accepted under the
//! real @bsv/sdk Spend). The AST has no let-expression, so every hoist that
//! would reorder evaluation is refused with the diagnostic shared by all seven
//! tiers.
//!
//! Proves: the same refused / accepted shapes as the TS reference
//! (packages/runar-compiler/src/__tests__/03b-expand-fixed-arrays.test.ts).
//! Does not prove on-chain behaviour; the TS VM test and
//! conformance/negatives/N120-N122 cover that across tiers.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const expand_fixed_arrays = @import("../passes/expand_fixed_arrays.zig");

const DIAG = "FixedArray index would be evaluated out of source order";

fn expandBody(work: std.mem.Allocator, comptime body: []const u8) !expand_fixed_arrays.Result {
    const src =
        \\class Peek extends StatefulSmartContract {
        \\  readonly enabled: FixedArray<bigint, 2> = [1n, 0n];
        \\  slots: FixedArray<bigint, 2> = [0n, 0n];
        \\  cursor: bigint;
        \\  constructor(cursor: bigint) { super(cursor); this.cursor = cursor; }
        \\  public release(k: bigint, c: boolean) {
        \\
    ++ "    " ++ body ++ "\n" ++
        \\  }
        \\}
    ;
    const parsed = compiler_api.parseSource(work, src, "Peek.runar.ts");
    if (parsed.errors.len > 0) {
        for (parsed.errors) |e| std.debug.print("parse error: {s}\n", .{e});
        return error.ParseFailed;
    }
    return expand_fixed_arrays.expand(work, parsed.contract.?);
}

fn hasDiag(res: expand_fixed_arrays.Result) bool {
    for (res.errors) |e| {
        if (std.mem.indexOf(u8, e.message, DIAG) != null) return true;
    }
    return false;
}

const refused = [_][]const u8{
    "assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);",
    "assert(++this.cursor + this.enabled[this.cursor % 2n] > 0n);",
    "assert(this.addRawOutput(1n, toByteString(\"00\")) === this.enabled[this.cursor % 2n]);",
    "assert(k > 0n && this.enabled[k - 1n] === 1n);",
    "assert(k === 0n || this.enabled[k - 1n] === 1n);",
    "assert((c ? this.enabled[k + 1n] : 0n) === 0n);",
    "assert(this.cursor + this.enabled[++this.cursor % 2n] > 0n);",
    "this.slots[++this.cursor % 2n] = this.enabled[this.cursor % 2n]; assert(true);",
};

const accepted = [_][]const u8{
    "++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);",
    "assert(this.enabled[k - 1n] === 1n && k > 0n);",
    "assert((this.enabled[k + 1n] === 1n ? 1n : 0n) === 1n);",
    "assert(this.enabled[this.cursor % 2n] + ++this.cursor > 0n);",
    "const v = this.enabled[k + 1n]; assert(v === 1n);",
    "this.slots[this.cursor % 2n] = ++this.cursor; assert(true);",
};

test "N-048: refuses a hoist that reorders evaluation" {
    inline for (refused) |body| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const res = try expandBody(arena.allocator(), body);
        if (!hasDiag(res)) {
            std.debug.print("expected the hoist-order refusal for: {s}\n", .{body});
            return error.TestExpectedRefusal;
        }
    }
}

test "N-048: accepts an order-preserving hoist" {
    inline for (accepted) |body| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const res = try expandBody(arena.allocator(), body);
        if (hasDiag(res)) {
            std.debug.print("unexpected hoist-order refusal for: {s}\n", .{body});
            return error.TestUnexpectedRefusal;
        }
    }
}

test "N-048: split form binds the index after the increment" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const res = try expandBody(arena.allocator(), "++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);");
    try std.testing.expectEqual(@as(usize, 0), res.errors.len);
    var release: ?[]const @import("../ir/types.zig").Statement = null;
    for (res.contract.methods) |m| {
        if (std.mem.eql(u8, m.name, "release")) release = m.body;
    }
    const body = release.?;
    try std.testing.expect(body[0] != .const_decl);
    try std.testing.expect(body[1] == .const_decl);
    try std.testing.expect(std.mem.startsWith(u8, body[1].const_decl.name, "__idx_"));
}
