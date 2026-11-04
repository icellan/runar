//! N-142 (Zig twin of F-200) — .runar.sol leading-underscore stripping applies
//! to CONSTRUCTOR params only.
//!
//! `parseSolParams` used to strip a leading `_` from every parameter, but only
//! `parseSolConstructor` renames its body to match. So a METHOD param `_x` was
//! declared as `x` while the body still read `_x`:
//!
//!   - unbound: `function check(bigint _x) public { require(_x == target); }`
//!     failed to compile (TS compiles it);
//!   - silent: `function inc(bigint _count) public { count++; }` declared a
//!     param `count` that shadowed the property, and a different script came
//!     out of this tier than out of TS;
//!   - inter: both at once.
//!
//! The rule is the TS reference's (01-parse-sol.ts): `parseConstructor` strips
//! `_` and renames the body; `parseFunction` keeps param names verbatim.
//!
//! What this proves: in the Zig tier, method params keep their `_` name, the
//! constructor still strips it, the bare `count++` stays a property write, and
//! all three shapes compile (fold-ON default) to the TS reference bytes
//! (sha256-pinned, the same pins as
//! conformance/negatives/sol-method-param-underscore-parity.test.ts).
//! What it does NOT prove: other tiers (the 7-tier pin lives in that
//! conformance test), fold-OFF output, or on-chain spend behaviour.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const UNBOUND =
    \\pragma runar ^0.1.0;
    \\
    \\contract F200Unbound is SmartContract {
    \\    bigint immutable target;
    \\
    \\    constructor(bigint _target) {
    \\        target = _target;
    \\    }
    \\
    \\    function check(bigint _x) public {
    \\        require(_x == target);
    \\    }
    \\}
    \\
;

const SILENT =
    \\pragma runar ^0.1.0;
    \\
    \\contract F200Silent is StatefulSmartContract {
    \\    bigint count;
    \\
    \\    constructor(bigint _count) {
    \\        count = _count;
    \\    }
    \\
    \\    function inc(bigint _count) public {
    \\        count++;
    \\    }
    \\}
    \\
;

const INTER =
    \\pragma runar ^0.1.0;
    \\
    \\contract F200Inter is StatefulSmartContract {
    \\    bigint count;
    \\
    \\    constructor(bigint _count) {
    \\        count = _count;
    \\    }
    \\
    \\    function inc(bigint _count) public {
    \\        count++;
    \\        require(_count > 0);
    \\    }
    \\}
    \\
;

fn hexSha(src: []const u8, file: []const u8) ![64]u8 {
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, src, file);
    defer result.deinit(allocator);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(result.script_hex, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

test "N-142: .sol method param keeps its underscore, constructor param is stripped" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = compiler_api.parseSource(arena.allocator(), UNBOUND, "F200Unbound.runar.sol");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract orelse return error.TestExpectedContract;
    try std.testing.expectEqual(@as(usize, 1), c.methods.len);
    try std.testing.expectEqual(@as(usize, 1), c.methods[0].params.len);
    try std.testing.expectEqualStrings("_x", c.methods[0].params[0].name);
    try std.testing.expectEqual(@as(usize, 1), c.constructor.params.len);
    try std.testing.expectEqualStrings("target", c.constructor.params[0].name);
}

test "N-142: .sol unbound shape compiles to the TS reference bytes" {
    const allocator = std.testing.allocator;
    const result = try compiler_api.compileSource(allocator, UNBOUND, "F200Unbound.runar.sol");
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings("009c", result.script_hex);
}

test "N-142: .sol silent shape keeps the state write" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const r = compiler_api.parseSource(arena.allocator(), SILENT, "F200Silent.runar.sol");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract orelse return error.TestExpectedContract;
    const m = c.methods[0];
    try std.testing.expectEqual(@as(usize, 1), m.params.len);
    try std.testing.expectEqualStrings("_count", m.params[0].name);
    const es = switch (m.body[0]) {
        .expr_stmt => |e| e,
        else => return error.TestExpectedExprStmt,
    };
    const inc = switch (es.expr) {
        .increment => |i| i,
        else => return error.TestExpectedIncrement,
    };
    try std.testing.expect(inc.operand == .property_access);

    const got = try hexSha(SILENT, "F200Silent.runar.sol");
    try std.testing.expectEqualStrings("484142b25662c6a0a0126f11b1d4700fd79632224dc38c6ae869c889e5fe30d5", &got);
}

test "N-142: .sol inter shape compiles to the TS reference bytes" {
    const got = try hexSha(INTER, "F200Inter.runar.sol");
    try std.testing.expectEqualStrings("29956ebf68e8510b65a74f18a47e5851f322bf6dc2d0981b45ee301f2aaae575", &got);
}
