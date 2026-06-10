// BUG-008 follow-up: source-parser size-guard regression tests.

const std = @import("std");
const testing = std.testing;
const input_limits = @import("input_limits.zig");
const compiler_api = @import("../compiler_api.zig");

test "assertSourceBytesUnderLimit rejects oversized input" {
    const allocator = testing.allocator;
    const oversized = try allocator.alloc(u8, input_limits.MAX_SOURCE_BYTES + 1);
    defer allocator.free(oversized);
    @memset(oversized, ' ');

    const result = input_limits.assertSourceBytesUnderLimit(oversized);
    try testing.expectError(error.SourceSizeExceeded, result);
}

test "assertSourceBytesUnderLimit accepts at-limit input" {
    const allocator = testing.allocator;
    // At-limit (== MAX_SOURCE_BYTES) is accepted; cap is strict > only.
    const sized = try allocator.alloc(u8, input_limits.MAX_SOURCE_BYTES);
    defer allocator.free(sized);
    @memset(sized, ' ');

    try input_limits.assertSourceBytesUnderLimit(sized);
}

test "compileSource returns SourceSizeExceeded on oversized input" {
    const allocator = testing.allocator;
    const oversized = try allocator.alloc(u8, input_limits.MAX_SOURCE_BYTES + 1);
    defer allocator.free(oversized);
    @memset(oversized, ' ');

    const result = compiler_api.compileSource(allocator, oversized, "Counter.runar.zig");
    try testing.expectError(error.SourceSizeExceeded, result);
}

test "compileSource accepts small but invalid input without tripping size guard" {
    const allocator = testing.allocator;
    // A short snippet — too short to be a valid contract but well below the
    // size cap. We expect *some* downstream error (ParseFailed etc.) but
    // NOT SourceSizeExceeded.
    const src = "// empty\n";
    const result = compiler_api.compileSource(allocator, src, "Counter.runar.zig");
    if (result) |r| {
        // Unexpected success path; clean up.
        r.deinit(allocator);
        try testing.expect(false);
    } else |err| {
        try testing.expect(err != error.SourceSizeExceeded);
    }
}
