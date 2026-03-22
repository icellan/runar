const std = @import("std");
const bsvz = @import("bsvz");
const builtins = @import("builtins.zig");
const wots = @import("wots_helpers.zig");

pub const RabinProof = struct {
    sig: []const u8,
    padding: []const u8,
};

pub const rabin_test_key_n = [_]u8{
    0x95, 0x0b, 0x36, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x63,
    0x62, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

pub fn oraclePriceProof(price: i64) ?RabinProof {
    return switch (price) {
        60_000 => .{
            .sig = &[_]u8{
                0x35, 0xf7, 0x5f, 0x63, 0x38, 0x4c, 0xae, 0x3c, 0x1f,
                0x87, 0x4e, 0x64, 0xd0, 0xd4, 0x69, 0x2e, 0xa1, 0xcb,
                0x59, 0x5d, 0xf5, 0x2f, 0xe1, 0x49, 0x30, 0x74, 0x5c,
                0x43, 0xe1, 0x6f, 0x6e, 0xb0, 0x01,
            },
            .padding = &[_]u8{0x04},
        },
        50_000 => .{
            .sig = &[_]u8{
                0x60, 0xde, 0x12, 0xb9, 0x8e, 0xd7, 0x90, 0xbe, 0x19,
                0xc8, 0xdc, 0x19, 0x93, 0x57, 0x0a, 0x57, 0x75, 0x01,
                0x16, 0x7f, 0x2a, 0x22, 0xd5, 0xc5, 0x79, 0x7a, 0xe0,
                0x3e, 0x88, 0x09, 0x5a, 0xdc, 0x02,
            },
            .padding = &[_]u8{0x01},
        },
        30_000 => .{
            .sig = &[_]u8{
                0x33, 0x8d, 0x5d, 0x3c, 0xd4, 0x2f, 0xe0, 0xe0, 0x8f,
                0x5b, 0xb4, 0x71, 0x21, 0x19, 0x5d, 0x1f, 0xc7, 0x4f,
                0xa0, 0x7c, 0x4e, 0x97, 0x2b, 0xee, 0xd5, 0xd8, 0xf0,
                0x03, 0x6a, 0x8a, 0x29, 0x25, 0x01,
            },
            .padding = &[_]u8{0x00},
        },
        else => null,
    };
}

pub const wots_n = wots.wots_n;
pub const wots_w = wots.wots_w;
pub const wots_len1 = wots.wots_len1;
pub const wots_len2 = wots.wots_len2;
pub const wots_len = wots.wots_len;
pub const wotsPublicKeyFromSeed = wots.publicKeyFromSeed;
pub const wotsSignDeterministic = wots.signDeterministic;

pub fn buildP2pkhOutput(recipient_pkh: []const u8, satoshis: i64) []const u8 {
    return builtins.buildChangeOutput(recipient_pkh, satoshis);
}

pub fn mockPreimageForOutputs(outputs: []const []const u8) []const u8 {
    const output_views = parseSerializedOutputs(std.heap.page_allocator, outputs) catch @panic("invalid serialized output");
    defer {
        for (output_views) |output| std.heap.page_allocator.free(output.locking_script.bytes);
        std.heap.page_allocator.free(output_views);
    }

    const output_hash = bsvz.transaction.Output.hashAll(std.heap.page_allocator, output_views) catch @panic("failed to hash outputs");
    return builtins.mockPreimage(.{ .outputHash = output_hash.bytes[0..] });
}

fn parseSerializedOutputs(
    allocator: std.mem.Allocator,
    outputs: []const []const u8,
) ![]bsvz.transaction.Output {
    const parsed = try allocator.alloc(bsvz.transaction.Output, outputs.len);
    errdefer {
        for (parsed[0..outputs.len]) |output| {
            if (output.locking_script.bytes.len != 0) allocator.free(output.locking_script.bytes);
        }
        allocator.free(parsed);
    }

    @memset(parsed, .{
        .satoshis = 0,
        .locking_script = bsvz.script.Script.init(&.{}),
    });

    for (outputs, 0..) |output_bytes, index| {
        parsed[index] = try parseSerializedOutput(allocator, output_bytes);
    }

    return parsed;
}

fn parseSerializedOutput(
    allocator: std.mem.Allocator,
    output_bytes: []const u8,
) !bsvz.transaction.Output {
    const parsed = bsvz.transaction.Output.parse(allocator, output_bytes) catch return error.InvalidSerializedOutput;
    if (parsed.len != output_bytes.len) return error.InvalidSerializedOutput;

    const locking_script = try allocator.dupe(u8, parsed.output.locking_script.bytes);
    return .{
        .satoshis = parsed.output.satoshis,
        .locking_script = bsvz.script.Script.init(locking_script),
    };
}

test "deterministic WOTS helpers round trip through the runtime verifier" {
    const test_keys = @import("test_keys.zig");

    const seed = [_]u8{0x42} ** 32;
    const pub_seed = [_]u8{0x13} ** 32;
    const msg = builtins.signTestMessage(test_keys.ALICE);
    defer std.heap.page_allocator.free(@constCast(msg));

    const pk = wotsPublicKeyFromSeed(&seed, &pub_seed);
    const sig = wotsSignDeterministic(msg, &seed, &pub_seed);

    try std.testing.expect(builtins.verifyWOTS(msg, &sig, &pk));
}

test "oracle price Rabin fixtures verify against the shared test modulus" {
    const proof = oraclePriceProof(60_000).?;
    const message = builtins.num2bin(@as(i64, 60_000), 8);
    defer std.heap.page_allocator.free(@constCast(message));

    try std.testing.expect(builtins.verifyRabinSig(message, proof.sig, proof.padding, &rabin_test_key_n));
    try std.testing.expect(!builtins.verifyRabinSig("wrong-message", proof.sig, proof.padding, &rabin_test_key_n));
}

test "P2PKH output and mock preimage helpers compose expected output hashes" {
    const test_keys = @import("test_keys.zig");
    const out1 = buildP2pkhOutput(test_keys.ALICE.pubKeyHash, 100);
    const out2 = buildP2pkhOutput(test_keys.BOB.pubKeyHash, 200);
    defer std.heap.page_allocator.free(out1);
    defer std.heap.page_allocator.free(out2);

    const output_views = try parseSerializedOutputs(std.heap.page_allocator, &.{ out1, out2 });
    defer {
        for (output_views) |output| std.heap.page_allocator.free(output.locking_script.bytes);
        std.heap.page_allocator.free(output_views);
    }

    const expected_hash = try bsvz.transaction.Output.hashAll(std.heap.page_allocator, output_views);

    const preimage = mockPreimageForOutputs(&.{ out1, out2 });
    defer std.heap.page_allocator.free(preimage);

    try std.testing.expectEqualSlices(u8, &expected_hash.bytes, builtins.extractOutputHash(preimage));
}

test "buildP2pkhOutput emits canonical serialized P2PKH output bytes" {
    const test_keys = @import("test_keys.zig");
    const out = buildP2pkhOutput(test_keys.ALICE.pubKeyHash, 100);
    defer std.heap.page_allocator.free(out);

    var pubkey_hash: bsvz.crypto.Hash160 = undefined;
    @memcpy(&pubkey_hash.bytes, test_keys.ALICE.pubKeyHash[0..20]);
    const locking_script = bsvz.script.templates.p2pkh.encode(pubkey_hash);
    const expected_output = bsvz.transaction.Output{
        .satoshis = 100,
        .locking_script = bsvz.script.Script.init(&locking_script),
    };
    const expected = try expected_output.serialize(std.heap.page_allocator);
    defer std.heap.page_allocator.free(expected);

    try std.testing.expectEqualSlices(u8, expected, out);
}
