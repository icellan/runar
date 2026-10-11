//! N-038 (R64) — a stateful `@sighash SINGLE|FORKID` method's continuation.
//!
//! BIP-143 SINGLE commits hashOutputs to hash256(output[inputIndex]) only, so
//! under a SINGLE base the auto-injected continuation hashes the method's own
//! output and nothing else: no change segment, and no `_changePKH` /
//! `_changeAmount` method params. Before N-038 the continuation also hashed the
//! change output, so every SINGLE call with change > 0 was unspendable.
//!
//! What this proves: this tier compiles the N-038 contract
//! (conformance/sdk-call/SingleCounter.runar.ts, fold OFF) to the TS-stamped sdk-call pin byte-for-byte, with the SINGLE
//! `bump` ABI taking only `txPreimage` (and still non-terminal), while the
//! ALL `reset` keeps `_changePKH, _changeAmount, _newAmount, txPreimage`.
//! What it does NOT prove: the ANF IR (the other tiers compare
//! conformance/sdk-call/expected-ir.json), spendability (the sdk-call vector
//! Spend replay does), or other tiers.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const SRC_PATH = "../../conformance/sdk-call/SingleCounter.runar.ts";
const GOLDEN_PATH = "../../conformance/sdk-call/expected-script.hex";

test "N-038 SINGLE stateful continuation matches the golden and drops the change params" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const src = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, SRC_PATH, a, .limited(1 << 20));
    const golden_raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, GOLDEN_PATH, a, .limited(1 << 20));
    const golden = std.mem.trim(u8, golden_raw, " \r\n\t");

    const res = try compiler_api.compileSourceWithOptions(a, src, "SingleCounter.runar.ts", true);
    const json = res.artifact_json.?;
    try std.testing.expect(std.mem.indexOf(u8, json,
        "{\"name\":\"bump\",\"params\":[{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}],\"isPublic\":true,\"usesCodePart\":true,\"sigHashType\":67}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json,
        "{\"name\":\"reset\",\"params\":[{\"name\":\"_changePKH\",\"type\":\"Ripemd160\"},{\"name\":\"_changeAmount\",\"type\":\"bigint\"},{\"name\":\"_newAmount\",\"type\":\"bigint\"},{\"name\":\"txPreimage\",\"type\":\"SigHashPreimage\"}],\"isPublic\":true,\"usesCodePart\":true}") != null);
    try std.testing.expectEqualStrings(golden, res.script_hex);
}
