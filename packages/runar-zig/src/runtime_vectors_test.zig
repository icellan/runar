//! Runtime vectors — cross-SDK consistency check.
//!
//! Loads `conformance/runtime-vectors/hashes.json` (the cross-SDK source of
//! truth for `sha256Finalize`, `blake3Compress`, and `blake3Hash` outputs)
//! and asserts that the Zig SDK's runtime helpers in `builtins.zig`
//! produce the documented output byte-for-byte. Every other consumer
//! (TS / Java / Python / Go / Rust / Ruby) loads the same file and runs
//! the equivalent assertion; a divergence between any two runtime impls
//! shows up here.
//!
//! Reference: `_consumers` in the JSON file enumerates the per-SDK tests
//! that share these vectors.

const std = @import("std");
const builtins = @import("builtins.zig");

// `freeIfOwned` is the canonical helper for releasing a builtins-allocated
// ByteString — it tracks ownership via the global allocator the runtime
// helpers use. Re-exported from builtins.zig for tests.
const freeIfOwned = builtins.freeIfOwned;

fn hexDecodeAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHex;
    const out = try allocator.alloc(u8, hex.len / 2);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = try std.fmt.parseInt(u8, hex[i .. i + 2], 16);
    }
    return out;
}

fn hexEncodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    const charset = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = charset[b >> 4];
        out[i * 2 + 1] = charset[b & 0x0f];
    }
    return out;
}

/// Locate `conformance/runtime-vectors/hashes.json` by walking up from the
/// test process's current directory. `zig build test` runs with cwd =
/// packages/runar-zig; the conformance dir is two parents up. We keep the
/// walk generic so the path works no matter where the test binary is
/// launched from.
fn loadVectors(allocator: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
    const initial = try std.process.currentPathAlloc(std.testing.io, allocator);
    var current: []u8 = try allocator.dupe(u8, initial);
    allocator.free(initial);
    defer allocator.free(current);

    var found_data: ?[]u8 = null;
    walk: while (current.len > 0) {
        const candidate = try std.fs.path.join(allocator, &.{ current, "conformance", "runtime-vectors", "hashes.json" });
        defer allocator.free(candidate);
        const data = std.Io.Dir.cwd().readFileAlloc(std.testing.io, candidate, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound => {
                const parent = std.fs.path.dirname(current) orelse break :walk;
                if (std.mem.eql(u8, parent, current)) break :walk;
                const parent_dup = try allocator.dupe(u8, parent);
                allocator.free(current);
                current = parent_dup;
                continue :walk;
            },
            else => return err,
        };
        found_data = data;
        break :walk;
    }
    const data = found_data orelse return error.VectorsNotFound;
    defer allocator.free(data);
    return std.json.parseFromSlice(std.json.Value, allocator, data, .{});
}

test "runtime vectors: sha256Finalize matches every entry in hashes.json" {
    const allocator = std.testing.allocator;
    var parsed = try loadVectors(allocator);
    defer parsed.deinit();

    const root = parsed.value.object;
    const cases = root.get("sha256_finalize").?.array.items;
    try std.testing.expect(cases.len > 0);

    for (cases) |c| {
        const obj = c.object;
        const state_hex = obj.get("state").?.string;
        const remaining_hex = obj.get("remaining").?.string;
        const msg_bit_len = obj.get("msg_bit_len").?.integer;
        const expected_hex = obj.get("expected").?.string;

        const state = try hexDecodeAlloc(allocator, state_hex);
        defer allocator.free(state);
        const remaining = try hexDecodeAlloc(allocator, remaining_hex);
        defer allocator.free(remaining);

        const got = builtins.sha256Finalize(state, remaining, @intCast(msg_bit_len));
        defer freeIfOwned(got);
        const got_hex = try hexEncodeAlloc(allocator, got);
        defer allocator.free(got_hex);
        try std.testing.expectEqualStrings(expected_hex, got_hex);
    }
}

test "runtime vectors: blake3Compress matches every entry in hashes.json" {
    const allocator = std.testing.allocator;
    var parsed = try loadVectors(allocator);
    defer parsed.deinit();

    const root = parsed.value.object;
    const cases = root.get("blake3_compress").?.array.items;
    try std.testing.expect(cases.len > 0);

    for (cases) |c| {
        const obj = c.object;
        const state_hex = obj.get("state").?.string;
        const block_hex = obj.get("block").?.string;
        const expected_hex = obj.get("expected").?.string;

        const state = try hexDecodeAlloc(allocator, state_hex);
        defer allocator.free(state);
        const block = try hexDecodeAlloc(allocator, block_hex);
        defer allocator.free(block);

        const got = builtins.blake3Compress(state, block);
        defer freeIfOwned(got);
        const got_hex = try hexEncodeAlloc(allocator, got);
        defer allocator.free(got_hex);
        try std.testing.expectEqualStrings(expected_hex, got_hex);
    }
}

test "runtime vectors: blake3Hash matches every entry in hashes.json" {
    const allocator = std.testing.allocator;
    var parsed = try loadVectors(allocator);
    defer parsed.deinit();

    const root = parsed.value.object;
    const cases = root.get("blake3_hash").?.array.items;
    try std.testing.expect(cases.len > 0);

    for (cases) |c| {
        const obj = c.object;
        const input_hex = obj.get("input").?.string;
        const expected_hex = obj.get("expected").?.string;

        const input = try hexDecodeAlloc(allocator, input_hex);
        defer allocator.free(input);

        const got = builtins.blake3Hash(input);
        defer freeIfOwned(got);
        const got_hex = try hexEncodeAlloc(allocator, got);
        defer allocator.free(got_hex);
        try std.testing.expectEqualStrings(expected_hex, got_hex);
    }
}

test "runtime vectors: blake3_iv == sha256_iv (BLAKE3 spec)" {
    const allocator = std.testing.allocator;
    var parsed = try loadVectors(allocator);
    defer parsed.deinit();

    const constants = parsed.value.object.get("constants").?.object;
    const sha = constants.get("sha256_iv").?.string;
    const blake = constants.get("blake3_iv").?.string;
    try std.testing.expectEqualStrings(sha, blake);
}
