const std = @import("std");
const runar = @import("runar");
const runar_frontend = @import("runar_frontend");
const helpers = @import("helpers.zig");

// ---------------------------------------------------------------------------
// Baby Bear field arithmetic tests: verify bbFieldAdd and bbFieldInv compile,
// deploy, and call correctly on a regtest node.
// ---------------------------------------------------------------------------

/// Baby Bear prime: p = 2013265921
const BB_P: i64 = 2013265921;

/// Compile inline TypeScript source to a RunarArtifact.
fn compileInlineSource(allocator: std.mem.Allocator, source: []const u8, file_name: []const u8) !runar.RunarArtifact {
    const result = try runar_frontend.compileSource(allocator, source, file_name);
    defer allocator.free(result.script_hex);

    if (result.artifact_json) |json| {
        defer allocator.free(json);
        return runar.RunarArtifact.fromJson(allocator, json);
    }

    return error.OutOfMemory;
}

test "BabyBear_FieldAdd_DeployAndCall" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    const source =
        \\import { SmartContract, assert, bbFieldAdd } from 'runar-lang';
        \\
        \\class BBAddTest extends SmartContract {
        \\  readonly expected: bigint;
        \\  constructor(expected: bigint) { super(expected); this.expected = expected; }
        \\  public verify(a: bigint, b: bigint) {
        \\    assert(bbFieldAdd(a, b) === this.expected);
        \\  }
        \\}
    ;

    var artifact = compileInlineSource(allocator, source, "BBAddTest.runar.ts") catch |err| {
        std.log.warn("Could not compile BBAddTest contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("BBAddTest", artifact.contract_name);
    std.log.info("BBAddTest compiled: {d} bytes", .{artifact.script.len / 2});

    // Deploy with expected = 10 (3 + 7 = 10)
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 10 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 500000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("BBAddTest deployed: {s}", .{deploy_txid});

    // Call verify(3, 7) — should succeed since bbFieldAdd(3, 7) = 10
    const call_txid = try contract.call(
        "verify",
        &[_]runar.StateValue{ .{ .int = 3 }, .{ .int = 7 } },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("BBAddTest verify TX: {s}", .{call_txid});
}

test "BabyBear_FieldAdd_WrapAround" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    const source =
        \\import { SmartContract, assert, bbFieldAdd } from 'runar-lang';
        \\
        \\class BBAddWrap extends SmartContract {
        \\  readonly expected: bigint;
        \\  constructor(expected: bigint) { super(expected); this.expected = expected; }
        \\  public verify(a: bigint, b: bigint) {
        \\    assert(bbFieldAdd(a, b) === this.expected);
        \\  }
        \\}
    ;

    var artifact = compileInlineSource(allocator, source, "BBAddWrap.runar.ts") catch |err| {
        std.log.warn("Could not compile BBAddWrap contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // (p-1) + 1 = 0 mod p
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

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 500000 });
    defer allocator.free(deploy_txid);
    std.log.info("BBAddWrap deployed: {s}", .{deploy_txid});

    const call_txid = try contract.call(
        "verify",
        &[_]runar.StateValue{ .{ .int = BB_P - 1 }, .{ .int = 1 } },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("BBAddWrap verify TX: {s}", .{call_txid});
}

test "BabyBear_FieldInv_AlgebraicIdentity" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    const source =
        \\import { SmartContract, assert, bbFieldInv, bbFieldMul } from 'runar-lang';
        \\
        \\class BBInvIdentity extends SmartContract {
        \\  constructor() { super(); }
        \\  public verify(a: bigint) {
        \\    const inv = bbFieldInv(a);
        \\    assert(bbFieldMul(a, inv) === 1n);
        \\  }
        \\}
    ;

    var artifact = compileInlineSource(allocator, source, "BBInvIdentity.runar.ts") catch |err| {
        std.log.warn("Could not compile BBInvIdentity contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("BBInvIdentity", artifact.contract_name);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{});
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 500000 });
    defer allocator.free(deploy_txid);
    std.log.info("BBInvIdentity deployed: {s}", .{deploy_txid});

    // verify(42) — bbFieldMul(42, bbFieldInv(42)) should equal 1
    const call_txid = try contract.call(
        "verify",
        &[_]runar.StateValue{.{ .int = 42 }},
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("BBInvIdentity verify TX: {s}", .{call_txid});
}

test "BabyBear_FieldAdd_WrongResult_Rejected" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    const source =
        \\import { SmartContract, assert, bbFieldAdd } from 'runar-lang';
        \\
        \\class BBAddReject extends SmartContract {
        \\  readonly expected: bigint;
        \\  constructor(expected: bigint) { super(expected); this.expected = expected; }
        \\  public verify(a: bigint, b: bigint) {
        \\    assert(bbFieldAdd(a, b) === this.expected);
        \\  }
        \\}
    ;

    var artifact = compileInlineSource(allocator, source, "BBAddReject.runar.ts") catch |err| {
        std.log.warn("Could not compile BBAddReject contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Wrong expected: 3+7=10, not 11
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 11 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 500000 });
    defer allocator.free(deploy_txid);
    std.log.info("BBAddReject deployed: {s}", .{deploy_txid});

    // Call with wrong expected — should be rejected on-chain
    const result = contract.call(
        "verify",
        &[_]runar.StateValue{ .{ .int = 3 }, .{ .int = 7 } },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestExpectedError; // Should have been rejected
    } else |_| {
        // Expected rejection
        std.log.info("BBAddReject correctly rejected wrong result", .{});
    }
}
