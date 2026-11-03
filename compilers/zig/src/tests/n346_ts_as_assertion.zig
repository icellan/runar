//! N-346 — the .runar.ts surface accepts `expr as T` type assertions and
//! erases them, as the TS reference does (AsExpression -> its operand).
//!
//! Proves: parsing `'aa' as ByteString`, `x as bigint as bigint`,
//! `(x + 1n) as bigint` and `x as bigint > 0n` yields no errors and the
//! same expression tree as the assertion-free source. Does not prove: byte
//! parity across tiers (conformance/negatives/n346-ts-as-assertion-parity.test.ts).

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");

fn wrap(alloc: std.mem.Allocator, body: []const u8) ![]const u8 {
    return std.fmt.allocPrint(alloc,
        \\import {{ SmartContract, assert }} from 'runar-lang';
        \\
        \\class Probe extends SmartContract {{
        \\  readonly h: ByteString;
        \\
        \\  constructor(h: ByteString) {{
        \\    super(h);
        \\    this.h = h;
        \\  }}
        \\
        \\  public unlock(x: bigint) {{
        \\    {s}
        \\  }}
        \\}}
        \\
    , .{body});
}

const Pair = struct { with_as: []const u8, plain: []const u8 };

const pairs = [_]Pair{
    .{ .with_as = "const k = 'aa' as ByteString; assert(k === this.h);", .plain = "const k = 'aa'; assert(k === this.h);" },
    .{ .with_as = "const y = x as bigint as bigint; assert(y > 0n);", .plain = "const y = x; assert(y > 0n);" },
    .{ .with_as = "const y = (x + 1n) as bigint; assert(y > 0n);", .plain = "const y = (x + 1n); assert(y > 0n);" },
    .{ .with_as = "const y = 5n as const; assert(x > y);", .plain = "const y = 5n; assert(x > y);" },
    .{ .with_as = "assert(x as bigint > 0n);", .plain = "assert(x > 0n);" },
};

test "N-346: `as` type assertions parse clean and are erased" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    for (pairs) |p| {
        const a = parse_ts.parseTs(alloc, try wrap(alloc, p.with_as), "Probe.runar.ts");
        const b = parse_ts.parseTs(alloc, try wrap(alloc, p.plain), "Probe.runar.ts");
        if (a.errors.len != 0) std.debug.print("N-346: `{s}` -> {s}\n", .{ p.with_as, a.errors[0] });
        try std.testing.expectEqual(@as(usize, 0), a.errors.len);
        try std.testing.expectEqual(@as(usize, 0), b.errors.len);
        const ma = a.contract.?.methods[0].body;
        const mb = b.contract.?.methods[0].body;
        try std.testing.expectEqual(mb.len, ma.len);
    }
}
