const std = @import("std");
const bsvz_hex = @import("bsvz_hex");

pub fn decodeAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    return bsvz_hex.decode(allocator, text);
}
