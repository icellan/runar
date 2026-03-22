const std = @import("std");
const runar = @import("runar");

pub const slhdsa_pub_key_hex = "00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf";
pub const slhdsa_pub_key_hash_hex = "9c6d307b68ea3e1cfe30340e2146564bec3af795";
const slhdsa_sig_raw = @embedFile("slhdsa_sig.hex");
pub const slhdsa_sig_hex = std.mem.trimRight(u8, slhdsa_sig_raw[0..slhdsa_sig_raw.len], "\r\n");
pub const slhdsa_sig_len: usize = 7856;

pub const slhdsa_pub_key = runar.hex.decodeFixed(32, slhdsa_pub_key_hex);
pub const slhdsa_pub_key_hash = runar.hex.decodeFixed(20, slhdsa_pub_key_hash_hex);
