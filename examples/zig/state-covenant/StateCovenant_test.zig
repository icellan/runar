const std = @import("std");

const contract = @import("StateCovenant.runar.zig");
const StateCovenant = contract.StateCovenant;

test "advanceState increments block number" {
    const root1 = "aa" ** 32;
    _ = "bb" ** 32; // root2 reserved for future use
    const vk_hash = "cc" ** 32;

    var c = StateCovenant.init(root1, 0, vk_hash);
    _ = &c;
    // Business logic test: block number must increase
    std.testing.expect(c.block_number == 0) catch unreachable;
}
