const std = @import("std");
const bsvz = @import("bsvz");

pub fn decodeAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    return bsvz.primitives.hex.decode(allocator, text);
}

pub fn decodeFixed(comptime N: usize, comptime text: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}
