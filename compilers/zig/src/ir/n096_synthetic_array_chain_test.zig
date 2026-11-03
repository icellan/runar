//! N-096: the IR loader refuses a `syntheticArrayChain` the expand-fixed-arrays
//! pass could not have written, with the diagnostic shared by all 7 tiers
//! (`conformance/negatives/ir-synthetic-array-chain.test.ts` holds the corpus).
//! Before the rule this tier dropped the F-105 probe's 1100-level property from
//! the ABI and compiled.
//!
//! Proves: a 1100-level chain is refused with the shared words, a well-formed
//! nested 2x2 family loads, and a family that ends early is refused. Does not
//! prove the rest of the rule, which the conformance corpus covers in every
//! tier.

const std = @import("std");
const types = @import("types.zig");
const required_fields = @import("required_fields.zig");
const chain_rule = @import("synthetic_array_chain.zig");

fn prop(name: []const u8, chain: []const types.SyntheticArrayLevel) types.ANFProperty {
    return .{
        .name = name,
        .type_name = "bigint",
        .type_info = types.parseRunarType("bigint"),
        .readonly = true,
        .synthetic_array_chain = chain,
    };
}

test "N-096: the F-105 probe (1100 levels) is refused with the shared diagnostic" {
    const allocator = std.testing.allocator;
    const chain = try allocator.alloc(types.SyntheticArrayLevel, 1100);
    defer allocator.free(chain);
    for (chain) |*l| l.* = .{ .base = "deep", .index = 0, .length = 1 };
    const props = [_]types.ANFProperty{prop("deep", chain)};
    try std.testing.expectError(error.SyntheticArrayChainMalformed, chain_rule.check(allocator, &props));
    try std.testing.expectEqualStrings(
        "IR validation: malformed syntheticArrayChain on property 'deep': 1100 levels exceed the limit of 1023",
        required_fields.lastDiagnostic().?,
    );
}

test "N-096: a nested 2x2 family loads; one that ends early is refused" {
    const allocator = std.testing.allocator;
    const c00 = [_]types.SyntheticArrayLevel{ .{ .base = "g", .index = 0, .length = 2 }, .{ .base = "g__0", .index = 0, .length = 2 } };
    const c01 = [_]types.SyntheticArrayLevel{ .{ .base = "g", .index = 0, .length = 2 }, .{ .base = "g__0", .index = 1, .length = 2 } };
    const c10 = [_]types.SyntheticArrayLevel{ .{ .base = "g", .index = 1, .length = 2 }, .{ .base = "g__1", .index = 0, .length = 2 } };
    const c11 = [_]types.SyntheticArrayLevel{ .{ .base = "g", .index = 1, .length = 2 }, .{ .base = "g__1", .index = 1, .length = 2 } };
    const full = [_]types.ANFProperty{ prop("g__0__0", &c00), prop("g__0__1", &c01), prop("g__1__0", &c10), prop("g__1__1", &c11) };
    try chain_rule.check(allocator, &full);

    const short = [_]types.ANFProperty{ prop("g__0__0", &c00), prop("g__0__1", &c01), prop("g__1__0", &c10) };
    try std.testing.expectError(error.SyntheticArrayChainMalformed, chain_rule.check(allocator, &short));
    try std.testing.expectEqualStrings(
        "IR validation: malformed syntheticArrayChain on property 'g__1__0': 'g' ends here, before its element 'g__1__1'",
        required_fields.lastDiagnostic().?,
    );
}
