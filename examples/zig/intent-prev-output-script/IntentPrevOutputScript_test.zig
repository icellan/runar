const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const IntentPrevOutputScript = @import("IntentPrevOutputScript.runar.zig").IntentPrevOutputScript;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "intent-prev-output-script/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check IntentPrevOutputScript.runar.zig" {
    try runCompileChecks("IntentPrevOutputScript.runar.zig");
}

// Proves: bind() passes only when the witness the mock supplies for input 0 (runar.setMockPrevOutputScript, the native counterpart of the injected _prevOutScript_0 parameter) hashes (hash256) to expectedHash AND is non-empty; a witness with the wrong hash, no witness at all, and an empty witness whose hash is the expected one each abort with the Runar assertion. The intrinsic now enforces the same hash256(witness) == expectedHash assertion the compiler emits (N-375: the stub used to return an empty string and never abort, and was not re-exported).
// Does not prove: that the witness is the previous output script of a real input (the contract and the compiler deliberately do not bind that either, see the contract header), nor the 3-arg prefix form.

test "IntentPrevOutputScript bind passes for a witness that hashes to expectedHash" {
    const script = "prev-output-script";
    const prev = runar.setMockPrevOutputScript(0, script);
    defer _ = runar.setMockPrevOutputScript(0, prev);
    var c = IntentPrevOutputScript.init(runar.hash256(script), 0);
    c.bind();
    try std.testing.expectEqual(@as(i64, 1), c.count);
}

test "IntentPrevOutputScript bind aborts for a witness with the wrong hash" {
    try root.expectAssertFailure("intent-prev-output-script-wrong-hash");
}

test "IntentPrevOutputScript bind aborts when no witness was supplied" {
    try root.expectAssertFailure("intent-prev-output-script-no-witness");
}

test "IntentPrevOutputScript bind aborts for an empty witness with the matching hash" {
    try root.expectAssertFailure("intent-prev-output-script-empty-witness");
}
