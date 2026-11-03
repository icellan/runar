//! N-171 (sibling of F-274) — native `substr` must return what the compiled
//! script returns.
//!
//! `builtins.zig` is the runtime every native `.runar.zig` contract test
//! links against (re-exported as the public `runar` namespace in root.zig).
//! Its `substr` returned an empty `ByteString` for a negative `length`, or
//! for an in-range `start` paired with `length == 0` -- without ever
//! checking `start` against the data's size, or `start + length` against it
//! either -- instead of the abort OP_SPLIT's two chained splits actually
//! produce.
//!
//! The vectors in fixtures/n171-split-substr-builtins-onchain.json are
//! pinned against the EXECUTED SCRIPT on @bsv/sdk Spend.validate by
//! packages/runar-testing/src/__tests__/n171-split-substr-builtins-onchain.test.ts.
//! This file replays the `substr` rows' VALID cases through the native
//! runtime, so native == JSON == on-chain for every value substr can
//! actually produce.
//!
//! Proves: for every non-abort `substr` vector, the native builtin returns
//! the on-chain value.
//! Does NOT prove: native aborts. An `abort` vector now ends in a Zig
//! panic, which a test cannot observe in-process (matching
//! builtins_math_onchain_test.zig's documented limitation for the same
//! reason) -- `split`'s abort is exercised in-process instead through the
//! SDK ANF interpreter (sdk_anf_interpreter_n171_test.zig), which surfaces
//! an error value rather than panicking.

const std = @import("std");
const builtins = @import("builtins.zig");

const vectors_json = @embedFile("fixtures/n171-split-substr-builtins-onchain.json");

fn hexToBytesAlloc(a: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try a.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn bytesToHexAlloc(a: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try a.alloc(u8, bytes.len * 2);
    const charset = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = charset[b >> 4];
        out[i * 2 + 1] = charset[b & 0x0f];
    }
    return out;
}

test "N-171: native substr returns the on-chain value for every non-abort shared vector" {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, vectors_json, .{});
    defer parsed.deinit();

    const cases = parsed.value.object.get("cases").?.array.items;
    var checked: usize = 0;
    for (cases) |c| {
        const obj = c.object;
        const name = obj.get("fn").?.string;
        if (!std.mem.eql(u8, name, "substr")) continue;
        const expect = obj.get("expect").?;
        if (expect == .string and std.mem.eql(u8, expect.string, "abort")) continue;

        const data_hex = obj.get("data").?.string;
        const start: i64 = @intCast(obj.get("a").?.integer);
        const length: i64 = @intCast(obj.get("b").?.integer);
        const expect_hex = expect.string;

        const data = try hexToBytesAlloc(allocator, data_hex);
        defer allocator.free(data);

        // `builtins.substr` allocates its result via `std.heap.page_allocator`
        // internally (see builtins.zig), not the caller's allocator -- every
        // other native call site (examples/zig/token-ft, cross-covenant,
        // r1-k1-wallet) leaves it unfreed too, so this does the same rather
        // than freeing through the wrong allocator.
        const got = builtins.substr(data, start, length);
        const got_hex = try bytesToHexAlloc(allocator, got);
        defer allocator.free(got_hex);

        try std.testing.expectEqualStrings(expect_hex, got_hex);
        checked += 1;
    }
    try std.testing.expect(checked > 0);
}
