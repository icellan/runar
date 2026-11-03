const std = @import("std");

const root = @import("../examples_test.zig");
const contract = @import("StateCovenant.runar.zig");
const StateCovenant = contract.StateCovenant;
const witness = @import("witness.zig");

fn contractPath(comptime basename: []const u8) []const u8 {
    return "state-covenant/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check StateCovenant.runar.zig" {
    try runCompileChecks("StateCovenant.runar.zig");
}

test "StateCovenant init stores constructor arguments" {
    const w = witness.valid();
    const c = StateCovenant.init(w.preStateRoot, 0, w.verifyingKeyHash);
    try std.testing.expectEqual(@as(i64, 0), c.blockNumber);
    try std.testing.expectEqualSlices(u8, w.preStateRoot, c.stateRoot);
    try std.testing.expectEqualSlices(u8, w.verifyingKeyHash, c.verifyingKeyHash);
}

// F-168: the covenant's only real proof-verification logic (block-number
// monotonicity, pre-state-root binding, Baby Bear field check, Merkle
// commitment check, batch-hash binding) used to be entirely unexercised —
// the sole test here constructed the contract and asserted back a
// constructor literal without ever calling `advanceState`. This test and
// the five below it actually call the method.
test "StateCovenant advanceState accepts a valid proof and advances state" {
    const w = witness.valid();
    var c = StateCovenant.init(w.preStateRoot, 0, w.verifyingKeyHash);
    c.advanceState(
        w.newStateRoot,
        w.newBlockNumber,
        w.batchDataHash,
        w.preStateRoot,
        w.proofFieldA,
        w.proofFieldB,
        w.proofFieldC,
        w.merkleLeaf,
        w.merkleProof,
        w.merkleIndex,
    );
    try std.testing.expectEqual(w.newBlockNumber, c.blockNumber);
    try std.testing.expectEqualSlices(u8, w.newStateRoot, c.stateRoot);
}

// -- One deliberately invalid input per assertion -------------------------
//
// Each probe takes the same valid witness and corrupts exactly the field
// that the named assertion checks, leaving every other field valid so the
// native panic is attributable to that assertion and not an earlier one.

test "StateCovenant advanceState rejects a non-increasing block number" {
    try root.expectAssertFailure("state-covenant-block-not-increasing");
}

test "StateCovenant advanceState rejects a pre-state root that doesn't match current state" {
    try root.expectAssertFailure("state-covenant-wrong-prestate-root");
}

test "StateCovenant advanceState rejects an invalid Baby Bear field proof" {
    try root.expectAssertFailure("state-covenant-wrong-babybear-proof");
}

test "StateCovenant advanceState rejects an invalid Merkle commitment proof" {
    try root.expectAssertFailure("state-covenant-wrong-merkle-proof");
}

test "StateCovenant advanceState rejects a batch data hash that doesn't bind the state transition" {
    try root.expectAssertFailure("state-covenant-wrong-batch-hash");
}
