const std = @import("std");

pub const slhdsa_pub_key_hex = "00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf";
pub const slhdsa_pub_key_hash_hex = "9c6d307b68ea3e1cfe30340e2146564bec3af795";
const slhdsa_sig_raw = @embedFile("slhdsa_sig.hex");
pub const slhdsa_sig_hex = std.mem.trimRight(u8, slhdsa_sig_raw[0..slhdsa_sig_raw.len], "\r\n");
pub const slhdsa_sig_len: usize = 7856;

fn decodeHexFixed(comptime N: usize, comptime hex: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

pub const slhdsa_pub_key = decodeHexFixed(32, slhdsa_pub_key_hex);
pub const slhdsa_pub_key_hash = decodeHexFixed(20, slhdsa_pub_key_hash_hex);
