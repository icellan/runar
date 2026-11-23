//! D12 PQ-F1: a wrong-length WOTS+ public key deployed silently and the output
//! refused the owner's valid signature forever (the compiled verifier splits
//! the key at 32 bytes). `RunarContract.init` now refuses a constructor arg
//! loaded straight into a PQ verifier's pk operand when its length is wrong
//! (verifyWOTS 64 bytes; verifySLHDSA_SHA2_* 32 / 48 / 64).
//!
//! Proves: for the Zig compiler's artifact of
//!   class PqWots extends StatefulSmartContract {
//!     readonly pk: ByteString; n: bigint;
//!     public spend(msg, sig) { assert(verifyWOTS(msg, sig, this.pk)); this.n = this.n + 1n; }
//!   }
//! a 64-byte pk is accepted and 0 / 32 / 63 / 65 / 128-byte pks are refused.
//! PQ-F1: a stateless artifact (no ANF) is checked from its `pqPubKeyParams`,
//! and the refusal records the message shared by all seven SDKs.
//! Does NOT prove: SLH-DSA sets (same table, not executed here: their
//! artifacts are hundreds of KB), hash-committed keys.

const std = @import("std");
const types = @import("sdk_types.zig");
const contract_mod = @import("sdk_contract.zig");

// Predates `pqPubKeyParams` (compiled before PQ-F1), so it exercises the
// ANF fallback for older stateful artifacts. Do not restamp it.
const ARTIFACT_JSON = @embedFile("fixtures/d12-pq-wots-artifact.json");
// PQ-F1: a stateless verifyWOTS artifact from the Zig compiler; it carries no
// ANF, only `pqPubKeyParams`.
const STATELESS_JSON = @embedFile("fixtures/pq-f1-stateless-wots-artifact.json");
const errors_mod = @import("sdk_errors.zig");

test "D12 PQ-F1: a wrong-length verifyWOTS public key is refused at init" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, ARTIFACT_JSON);
    defer artifact.deinit();

    const good = "ab" ** 64;
    {
        const ctor = [_]types.StateValue{ .{ .bytes = good }, .{ .int = 0 } };
        var c = try contract_mod.RunarContract.init(allocator, &artifact, &ctor);
        c.deinit();
    }
    const bads = [_][]const u8{ "", "ab" ** 32, "ab" ** 63, "ab" ** 65, "ab" ** 128 };
    for (bads) |bad| {
        const ctor = [_]types.StateValue{ .{ .bytes = bad }, .{ .int = 0 } };
        if (contract_mod.RunarContract.init(allocator, &artifact, &ctor)) |c| {
            var cc = c;
            cc.deinit();
            std.debug.print("pk of {d} bytes was accepted\n", .{bad.len / 2});
            return error.TestExpectedRefusal;
        } else |e| try std.testing.expectEqual(contract_mod.ContractError.InvalidConstructorArg, e);
    }
}

test "PQ-F1: a stateless artifact is checked from pqPubKeyParams, with the shared message" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, STATELESS_JSON);
    defer artifact.deinit();
    try std.testing.expect(artifact.anf_json == null);
    try std.testing.expect(artifact.pq_pub_key_params != null);

    {
        const ctor = [_]types.StateValue{.{ .bytes = "ab" ** 64 }};
        var c = try contract_mod.RunarContract.init(allocator, &artifact, &ctor);
        c.deinit();
    }
    {
        const ctor = [_]types.StateValue{.{ .bytes = "ab" ** 32 }};
        try std.testing.expectError(contract_mod.ContractError.InvalidConstructorArg, contract_mod.RunarContract.init(allocator, &artifact, &ctor));
        try std.testing.expectEqualStrings(
            "RunarContract: constructor arg 'pk' is the verifyWOTS public key and must be exactly 64 bytes, got 32. " ++
                "A locking script built from it would refuse every valid signature, so the output could never be spent (PQ-F1)",
            errors_mod.lastPqPubKeyMessage(),
        );
    }
    const bads = [_][]const u8{ "", "ab" ** 63, "ab" ** 65 };
    for (bads) |bad| {
        const ctor = [_]types.StateValue{.{ .bytes = bad }};
        try std.testing.expectError(contract_mod.ContractError.InvalidConstructorArg, contract_mod.RunarContract.init(allocator, &artifact, &ctor));
    }
}
