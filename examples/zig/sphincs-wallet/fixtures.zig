const std = @import("std");
const runar = @import("runar");

pub const slhdsa_pub_key_hex = "00000000000000000000000000000000b253ffb61412a32b56e07eb091eef8c0";
pub const slhdsa_pub_key_hash_hex = "7e2a29a216baeb92f04424ba0a27073f4496677b";
const slhdsa_sig_raw = @embedFile("slhdsa_sig.hex");
pub const slhdsa_sig_hex = std.mem.trimEnd(u8, slhdsa_sig_raw[0..slhdsa_sig_raw.len], "\r\n");
pub const slhdsa_sig_len: usize = 7856;

pub const slhdsa_pub_key = runar.hex.decodeFixed(32, slhdsa_pub_key_hex);
pub const slhdsa_pub_key_hash = runar.hex.decodeFixed(20, slhdsa_pub_key_hash_hex);
