const std = @import("std");
const root = @import("../examples_test.zig");
const runar = @import("runar");
const IntentOutputP2PKH = @import("IntentOutputP2PKH.runar.zig").IntentOutputP2PKH;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "intent-output-p2pkh/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check IntentOutputP2PKH.runar.zig" {
    try runCompileChecks("IntentOutputP2PKH.runar.zig");
}

// Proves: payBond() passes only when output 0 of the serialised outputs the mock exposes (runar.setMockSerialisedOutputs, the native counterpart of the injected _serialisedOutputs witness) is a standard P2PKH paying bondAmount to bondPKH; a different pubkey hash, a different amount, or no outputs at all aborts with the Runar assertion. Also pins that requireOutputP2PKH is reachable as runar.requireOutputP2PKH (N-375: not re-exported before).
// Does not prove: the hash256(_serialisedOutputs) == extractOutputHash(txPreimage) commitment (the native call has no preimage to bind it to; that is a compiled-script property), nor the output-index-0-only refusal in the compiler.

test "IntentOutputP2PKH payBond passes for the exact P2PKH output" {
    const pkh = runar.hash160(runar.ALICE.pubKey);
    const prev = runar.setMockSerialisedOutputs(runar.buildChangeOutput(pkh, 5000));
    defer _ = runar.setMockSerialisedOutputs(prev);
    var c = IntentOutputP2PKH.init(pkh, 5000, 0);
    c.payBond();
}

test "IntentOutputP2PKH payBond aborts for a different pubkey hash" {
    try root.expectAssertFailure("intent-output-p2pkh-wrong-pkh");
}

test "IntentOutputP2PKH payBond aborts for a different amount" {
    try root.expectAssertFailure("intent-output-p2pkh-wrong-amount");
}

test "IntentOutputP2PKH payBond aborts when no outputs were supplied" {
    try root.expectAssertFailure("intent-output-p2pkh-no-outputs");
}
