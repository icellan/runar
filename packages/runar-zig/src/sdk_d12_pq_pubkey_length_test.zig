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
//! Does NOT prove: SLH-DSA sets (same table, not executed here: their
//! artifacts are hundreds of KB), stateless artifacts (no ANF in the artifact),
//! hash-committed keys.

const std = @import("std");
const types = @import("sdk_types.zig");
const contract_mod = @import("sdk_contract.zig");

const ARTIFACT_JSON = @embedFile("fixtures/d12-pq-wots-artifact.json");

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
