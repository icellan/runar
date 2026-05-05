//! PrivateHelperOutputs integration test — 2026-04-30 audit regression
//! (F1 + F3).
//!
//! The contract delegates state mutation, addDataOutput, and addOutput
//! to private helpers. Before the F1 fix the auto-injection was a
//! shallow scan of the public method body, so these methods were
//! silently classified as terminal and the deploy + call cycle would
//! fail. Mirrors the TS / Go / Rust / Python / Ruby integration
//! tests for the same contract.

const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "PrivateHelperOutputs_Deploy_AndCommitChain" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    // The Zig DSL example uses the same surface as TS — both
    // formats are accepted by the runner since the parser
    // dispatches by extension. We use the Zig surface here for the
    // .runar.zig parity coverage.
    var artifact = try compile.compileContract(
        allocator,
        "examples/zig/private-helper-outputs/PrivateHelperOutputs.runar.zig",
    );
    defer artifact.deinit();

    std.log.info("PrivateHelperOutputs script: {d} bytes", .{artifact.script.len / 2});
    try std.testing.expect(artifact.isStateful());

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 0 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .satoshis = 5000 },
    );
    defer allocator.free(deploy_txid);

    // Three sequential commits — each spends the previous
    // continuation UTXO. Failure means the runtime hashOutputs
    // didn't match the compiled continuation, which is exactly
    // what F1's shallow-scan miss would produce for state-mutation
    // routed through a private helper.
    var i: i64 = 0;
    while (i < 3) : (i += 1) {
        const call_txid = try contract.call(
            "commit",
            &.{},
            rpc_provider.provider(),
            local_signer.signer(),
            .{ .new_state = &[_]runar.StateValue{.{ .int = i + 1 }} },
        );
        defer allocator.free(call_txid);
        try std.testing.expect(call_txid.len > 0);
    }
}
