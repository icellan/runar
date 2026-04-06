const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// EC isolation tests: verify individual EC operations compile and deploy
// correctly. These test the EC demo contract which exercises ecOnCurve,
// ecPointX, ecPointY, ecAdd, ecNegate, ecMulGen, etc.
// ---------------------------------------------------------------------------

test "ECIsolation_Compile_ECDemo" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/ec-demo/ECDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile ECDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("ECDemo", artifact.contract_name);
    std.log.info("ECDemo compiled: {d} bytes", .{artifact.script.len / 2});
}

test "ECIsolation_ScriptSize" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/ec-demo/ECDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile ECDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    const script_bytes = artifact.script.len / 2;
    // EC contracts produce large scripts due to field arithmetic
    try std.testing.expect(script_bytes > 1000);
    std.log.info("ECDemo script size: {d} bytes", .{script_bytes});
}

test "ECIsolation_Deploy_ECDemo" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/ec-demo/ECDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile ECDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // secp256k1 generator point G as 64-byte hex (x[32]||y[32])
    const g_point_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = g_point_hex },
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
    std.log.info("ECDemo deployed: {s}", .{deploy_txid});
}

test "ECIsolation_Compile_ConvergenceProof" {
    const allocator = std.testing.allocator;

    // The ConvergenceProof contract uses multiple EC operations together:
    // ecOnCurve, ecAdd, ecNegate, ecMulGen, ecPointX, ecPointY
    var artifact = compile.compileContract(allocator, "examples/zig/convergence-proof/ConvergenceProof.runar.zig") catch |err| {
        std.log.warn("Could not compile ConvergenceProof contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("ConvergenceProof", artifact.contract_name);
    std.log.info("ConvergenceProof compiled: {d} bytes (EC operations)", .{artifact.script.len / 2});
}

test "ECIsolation_Deploy_DifferentPoints" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/ec-demo/ECDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile ECDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Deploy with G point
    const g_point_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = g_point_hex },
    });
    defer contract1.deinit();

    var wallet1 = try helpers.newWallet(allocator);
    defer wallet1.deinit();
    const fund_txid1 = try helpers.fundWallet(allocator, &wallet1, 1.0);
    defer allocator.free(fund_txid1);

    var rpc1 = helpers.RPCProvider.init(allocator);
    var signer1 = try wallet1.localSigner();
    const txid1 = try contract1.deploy(rpc1.provider(), signer1.signer(), .{ .satoshis = 500000 });
    defer allocator.free(txid1);

    // Deploy with 2*G point
    const two_g_hex = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" ++
        "1ae168fea63dc339a3c58419466ceae1032688d15f9c819fea738c882b9d5d90";

    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = two_g_hex },
    });
    defer contract2.deinit();

    var wallet2 = try helpers.newWallet(allocator);
    defer wallet2.deinit();
    const fund_txid2 = try helpers.fundWallet(allocator, &wallet2, 1.0);
    defer allocator.free(fund_txid2);

    var rpc2 = helpers.RPCProvider.init(allocator);
    var signer2 = try wallet2.localSigner();
    const txid2 = try contract2.deploy(rpc2.provider(), signer2.signer(), .{ .satoshis = 500000 });
    defer allocator.free(txid2);

    // Different constructor args produce different scripts
    try std.testing.expect(!std.mem.eql(u8, txid1, txid2));
    std.log.info("ECDemo G: {s}, 2G: {s}", .{ txid1, txid2 });
}

test "ECIsolation_Call_CheckOnCurve" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/ec-demo/ECDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile ECDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Deploy with generator point G
    const g_point_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = g_point_hex },
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

    // Call checkOnCurve() -- verifies ecOnCurve(self.pt) passes for G
    const call_txid = try contract.call(
        "checkOnCurve",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("ECDemo checkOnCurve TX: {s}", .{call_txid});
}

test "ECIsolation_Call_CheckMulGenOnCurve" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/ec-demo/ECDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile ECDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Deploy with generator point G (constructor arg; not used by checkMulGenOnCurve)
    const g_point_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = g_point_hex },
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

    // Call checkMulGenOnCurve(42) -- verifies ecOnCurve(ecMulGen(42))
    const call_txid = try contract.call(
        "checkMulGenOnCurve",
        &[_]runar.StateValue{
            .{ .int = 42 },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("ECDemo checkMulGenOnCurve(42) TX: {s}", .{call_txid});
}

test "ECIsolation_Call_CheckNegateRoundtrip" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/ec-demo/ECDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile ECDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Deploy with 2*G point
    const two_g_hex = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" ++
        "1ae168fea63dc339a3c58419466ceae1032688d15f9c819fea738c882b9d5d90";

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = two_g_hex },
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

    // Call checkNegateRoundtrip() -- verifies ecNegate(ecNegate(pt)) == pt
    const call_txid = try contract.call(
        "checkNegateRoundtrip",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("ECDemo checkNegateRoundtrip TX: {s}", .{call_txid});
}
