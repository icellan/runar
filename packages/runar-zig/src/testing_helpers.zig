const std = @import("std");
const builtins = @import("builtins.zig");
const hex = @import("hex.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const RabinProof = struct {
    sig: []const u8,
    padding: []const u8,
};

pub fn decodeHexAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    return hex.decodeAlloc(allocator, text);
}

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

pub const wots_n = 32;
pub const wots_w = 16;
pub const wots_len1 = 64;
pub const wots_len2 = 3;
pub const wots_len = wots_len1 + wots_len2;

pub fn buildP2pkhOutput(recipient_pkh: []const u8, satoshis: i64) []const u8 {
    const amount_bytes = builtins.num2bin(satoshis, 8);
    defer std.heap.page_allocator.free(@constCast(amount_bytes));

    const script_prefix = builtins.cat("1976a914", recipient_pkh);
    defer std.heap.page_allocator.free(@constCast(script_prefix));
    const locking_script = builtins.cat(script_prefix, "88ac");
    defer std.heap.page_allocator.free(@constCast(locking_script));

    return builtins.cat(amount_bytes, locking_script);
}

pub fn mockPreimageForOutputs(outputs: []const []const u8) []const u8 {
    var all_outputs = std.ArrayList(u8){};
    defer all_outputs.deinit(std.heap.page_allocator);

    for (outputs) |output| {
        all_outputs.appendSlice(std.heap.page_allocator, output) catch @panic("OOM");
    }

    const output_hash = builtins.hash256(all_outputs.items);
    defer std.heap.page_allocator.free(@constCast(output_hash));
    return builtins.mockPreimage(.{ .outputHash = output_hash });
}

fn wotsF(pub_seed: []const u8, chain_idx: usize, step_idx: usize, msg: []const u8) [32]u8 {
    var input: [wots_n + 2 + wots_n]u8 = undefined;
    @memcpy(input[0..wots_n], pub_seed);
    input[wots_n] = @truncate(chain_idx);
    input[wots_n + 1] = @truncate(step_idx);
    @memcpy(input[wots_n + 2 ..], msg);

    var out: [32]u8 = undefined;
    Sha256.hash(&input, &out, .{});
    return out;
}

fn wotsChain(x: []const u8, start_step: usize, steps: usize, pub_seed: []const u8, chain_idx: usize) [32]u8 {
    var current: [32]u8 = undefined;
    @memcpy(&current, x[0..wots_n]);
    var j = start_step;
    while (j < start_step + steps) : (j += 1) {
        current = wotsF(pub_seed, chain_idx, j, &current);
    }
    return current;
}

fn wotsAllDigits(msg_hash: *const [32]u8) [wots_len]usize {
    var digits: [wots_len]usize = undefined;
    var checksum: usize = 0;
    for (msg_hash, 0..) |byte, index| {
        const high = (byte >> 4) & 0x0f;
        const low = byte & 0x0f;
        digits[index * 2] = high;
        digits[index * 2 + 1] = low;
        checksum += (wots_w - 1) - high;
        checksum += (wots_w - 1) - low;
    }
    var remaining = checksum;
    var i: usize = wots_len;
    while (i > wots_len1) {
        i -= 1;
        digits[i] = remaining % wots_w;
        remaining /= wots_w;
    }
    return digits;
}

fn wotsSecretKeyElement(seed: []const u8, index: usize) [32]u8 {
    var input: [wots_n + 4]u8 = undefined;
    @memcpy(input[0..wots_n], seed);
    std.mem.writeInt(u32, input[wots_n .. wots_n + 4], @intCast(index), .big);

    var out: [32]u8 = undefined;
    Sha256.hash(&input, &out, .{});
    return out;
}

pub fn wotsPublicKeyFromSeed(seed: []const u8, pub_seed: []const u8) [64]u8 {
    var endpoints: [wots_len * wots_n]u8 = undefined;
    for (0..wots_len) |i| {
        const sk_element = wotsSecretKeyElement(seed, i);
        const endpoint = wotsChain(&sk_element, 0, wots_w - 1, pub_seed, i);
        @memcpy(endpoints[i * wots_n ..][0..wots_n], &endpoint);
    }

    var root_hash: [32]u8 = undefined;
    Sha256.hash(&endpoints, &root_hash, .{});

    var out: [64]u8 = undefined;
    @memcpy(out[0..32], pub_seed);
    @memcpy(out[32..64], &root_hash);
    return out;
}

pub fn wotsSignDeterministic(message: []const u8, seed: []const u8, pub_seed: []const u8) [wots_len * wots_n]u8 {
    var msg_hash: [32]u8 = undefined;
    Sha256.hash(message, &msg_hash, .{});
    const digits = wotsAllDigits(&msg_hash);

    var sig: [wots_len * wots_n]u8 = undefined;
    for (0..wots_len) |i| {
        const sk_element = wotsSecretKeyElement(seed, i);
        const element = wotsChain(&sk_element, 0, digits[i], pub_seed, i);
        @memcpy(sig[i * wots_n ..][0..wots_n], &element);
    }
    return sig;
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

    const combined = builtins.cat(out1, out2);
    defer std.heap.page_allocator.free(@constCast(combined));
    const expected_hash = builtins.hash256(combined);
    defer std.heap.page_allocator.free(@constCast(expected_hash));

    const preimage = mockPreimageForOutputs(&.{ out1, out2 });
    defer std.heap.page_allocator.free(preimage);

    try std.testing.expectEqualSlices(u8, expected_hash, builtins.extractOutputHash(preimage));
}
