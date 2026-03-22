const std = @import("std");

const root = @import("../examples_test.zig");
const Counter = @import("Counter.runar.zig").Counter;

const contract_source = @embedFile("Counter.runar.zig");

test "compile-check Counter.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "Counter.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "Counter.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "Counter.runar.zig");
}

test "counter executes increment and decrement directly" {
    var counter = Counter.init(2);

    counter.increment();
    try std.testing.expectEqual(@as(i64, 3), counter.count);

    counter.decrement();
    try std.testing.expectEqual(@as(i64, 2), counter.count);
}

test "counter decrement at zero fails through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "counter-underflow");
}
