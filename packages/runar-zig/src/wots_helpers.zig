const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const wots_n = 32;
pub const wots_w = 16;
pub const wots_len1 = 64;
pub const wots_len2 = 3;
pub const wots_len = wots_len1 + wots_len2;

pub fn allDigits(msg_hash: *const [32]u8) [wots_len]usize {
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

pub fn chain(x: []const u8, start_step: usize, steps: usize, pub_seed: []const u8, chain_idx: usize) [32]u8 {
    var current: [32]u8 = undefined;
    @memcpy(&current, x[0..wots_n]);

    var j = start_step;
    while (j < start_step + steps) : (j += 1) {
        current = f(pub_seed, chain_idx, j, &current);
    }
    return current;
}

pub fn publicKeyFromSeed(seed: []const u8, pub_seed: []const u8) [64]u8 {
    var endpoints: [wots_len * wots_n]u8 = undefined;
    for (0..wots_len) |i| {
        const sk_element = secretKeyElement(seed, i);
        const endpoint = chain(&sk_element, 0, wots_w - 1, pub_seed, i);
        @memcpy(endpoints[i * wots_n ..][0..wots_n], &endpoint);
    }

    var root_hash: [32]u8 = undefined;
    Sha256.hash(&endpoints, &root_hash, .{});

    var out: [64]u8 = undefined;
    @memcpy(out[0..32], pub_seed);
    @memcpy(out[32..64], &root_hash);
    return out;
}

pub fn signDeterministic(message: []const u8, seed: []const u8, pub_seed: []const u8) [wots_len * wots_n]u8 {
    var msg_hash: [32]u8 = undefined;
    Sha256.hash(message, &msg_hash, .{});
    const digits = allDigits(&msg_hash);

    var sig: [wots_len * wots_n]u8 = undefined;
    for (0..wots_len) |i| {
        const sk_element = secretKeyElement(seed, i);
        const element = chain(&sk_element, 0, digits[i], pub_seed, i);
        @memcpy(sig[i * wots_n ..][0..wots_n], &element);
    }
    return sig;
}

fn f(pub_seed: []const u8, chain_idx: usize, step_idx: usize, msg: []const u8) [32]u8 {
    var input: [wots_n + 2 + wots_n]u8 = undefined;
    @memcpy(input[0..wots_n], pub_seed);
    input[wots_n] = @truncate(chain_idx);
    input[wots_n + 1] = @truncate(step_idx);
    @memcpy(input[wots_n + 2 ..], msg);

    var out: [32]u8 = undefined;
    Sha256.hash(&input, &out, .{});
    return out;
}

fn secretKeyElement(seed: []const u8, index: usize) [32]u8 {
    var input: [wots_n + 4]u8 = undefined;
    @memcpy(input[0..wots_n], seed);
    std.mem.writeInt(u32, input[wots_n .. wots_n + 4], @intCast(index), .big);

    var out: [32]u8 = undefined;
    Sha256.hash(&input, &out, .{});
    return out;
}
