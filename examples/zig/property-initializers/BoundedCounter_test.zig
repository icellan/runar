const std = @import("std");

const root = @import("../examples_test.zig");
const BoundedCounter = @import("BoundedCounter.runar.zig").BoundedCounter;

const contract_source = @embedFile("BoundedCounter.runar.zig");

test "compile-check BoundedCounter.runar.zig" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "BoundedCounter.runar.zig", .data = contract_source });

    const path = try std.fs.path.join(allocator, &.{ ".zig-cache", "tmp", tmp.sub_path[0..], "BoundedCounter.runar.zig" });
    defer allocator.free(path);
    try root.runar.compileCheckFile(allocator, path);
    try root.runar.compileCheckSource(allocator, contract_source, "BoundedCounter.runar.zig");
}

test "bounded counter defaults active and resets" {
    var counter = BoundedCounter.init(10);
    try std.testing.expect(counter.active);
    try std.testing.expectEqual(@as(i64, 0), counter.count);

    counter.increment(4);
    try std.testing.expectEqual(@as(i64, 4), counter.count);

    counter.reset();
    try std.testing.expectEqual(@as(i64, 0), counter.count);
}

test "bounded counter overflow fails through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "bounded-counter-overflow");
}

test "bounded counter inactive flag fails through the real contract assertion path" {
    try root.runar.expectAssertFailure(std.testing.allocator, "bounded-counter-inactive");
}
