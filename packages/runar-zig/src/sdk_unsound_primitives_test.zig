//! R-062 / CL-BUG-105 — see sdk_errors.zig for the finding.
//!
//! Mirrors packages/runar-sdk/src/__tests__/unsound-primitives.test.ts.

const std = @import("std");
const errors_mod = @import("sdk_errors.zig");
const types = @import("sdk_types.zig");

test "R-062: an ordinary artifact deploys with or without an acknowledgement" {
    const none: []const []const u8 = &.{};
    const some: []const []const u8 = &.{"verifySP1FRI"};
    try errors_mod.assertUnsoundPrimitivesAcknowledged(&.{}, none, "Counter.deploy");
    try errors_mod.assertUnsoundPrimitivesAcknowledged(&.{}, some, "Counter.deploy");
}

test "R-062: an unsound artifact is refused without an acknowledgement" {
    errors_mod.last_unsound = null;
    const declared: []const []const u8 = &.{"verifySP1FRI"};
    const none: []const []const u8 = &.{};
    try std.testing.expectError(
        error.UnsoundPrimitiveNotAcknowledged,
        errors_mod.assertUnsoundPrimitivesAcknowledged(declared, none, "Sp1Rollup.deploy"),
    );
    const rec = errors_mod.last_unsound orelse return error.TestExpectedRecordedContext;
    try std.testing.expectEqualStrings("verifySP1FRI", rec.primitiveSlice());
    try std.testing.expectEqualStrings("Sp1Rollup.deploy", rec.contextSlice());
}

test "R-062: the acknowledgement must name every primitive" {
    const one: []const []const u8 = &.{"verifySP1FRI"};
    try errors_mod.assertUnsoundPrimitivesAcknowledged(one, one, "Sp1Rollup.deploy");

    const two: []const []const u8 = &.{ "verifySP1FRI", "someFutureStub" };
    try std.testing.expectError(
        error.UnsoundPrimitiveNotAcknowledged,
        errors_mod.assertUnsoundPrimitivesAcknowledged(two, one, "Sp1Rollup.deploy"),
    );
    const rec = errors_mod.last_unsound orelse return error.TestExpectedRecordedContext;
    try std.testing.expectEqualStrings("someFutureStub", rec.primitiveSlice());

    const other: []const []const u8 = &.{"somethingElse"};
    try std.testing.expectError(
        error.UnsoundPrimitiveNotAcknowledged,
        errors_mod.assertUnsoundPrimitivesAcknowledged(one, other, "Sp1Rollup.deploy"),
    );
}

test "R-062: the marker survives artifact JSON parsing, and is absent otherwise" {
    const a = std.testing.allocator;

    var marked = try types.RunarArtifact.fromJson(a,
        \\{"version":"v","contractName":"Sp1Rollup","script":"51","unsoundPrimitives":["verifySP1FRI"]}
    );
    defer marked.deinit();
    try std.testing.expectEqual(@as(usize, 1), marked.unsound_primitives.len);
    try std.testing.expectEqualStrings("verifySP1FRI", marked.unsound_primitives[0]);

    var plain = try types.RunarArtifact.fromJson(a,
        \\{"version":"v","contractName":"Counter","script":"51"}
    );
    defer plain.deinit();
    try std.testing.expectEqual(@as(usize, 0), plain.unsound_primitives.len);
}
