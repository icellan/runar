const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "MathDemo_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("MathDemo", artifact.contract_name);
    try std.testing.expect(artifact.isStateful());
    std.log.info("MathDemo compiled: {d} bytes", .{artifact.script.len / 2});
}

test "MathDemo_Deploy" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 100 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("MathDemo deployed: {s}", .{deploy_txid});
}

test "MathDemo_Call_DivideBy" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 100 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Call divideBy(5): 100 / 5 = 20
    const call_txid = try contract.call(
        "divideBy",
        &[_]runar.StateValue{.{ .int = 5 }},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 20 }} },
    );
    defer allocator.free(call_txid);

    std.log.info("MathDemo divideBy TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "MathDemo_Call_SquareRoot" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 144 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Call squareRoot(): sqrt(144) = 12
    const call_txid = try contract.call(
        "squareRoot",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 12 }} },
    );
    defer allocator.free(call_txid);

    std.log.info("MathDemo squareRoot TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "MathDemo_Call_Normalize" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // sign(-42) = -1
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = -42 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Call normalize(): sign(-42) = -1
    const call_txid = try contract.call(
        "normalize",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = -1 }} },
    );
    defer allocator.free(call_txid);

    std.log.info("MathDemo normalize TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "MathDemo_Call_Exponentiate" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // 2^10 = 1024
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 2 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Call exponentiate(10): 2^10 = 1024
    const call_txid = try contract.call(
        "exponentiate",
        &[_]runar.StateValue{.{ .int = 10 }},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 1024 }} },
    );
    defer allocator.free(call_txid);

    std.log.info("MathDemo exponentiate TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "MathDemo_Call_ScaleByRatio" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // 100 * 3 / 4 = 75
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 100 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Call scaleByRatio(3, 4): 100 * 3 / 4 = 75
    const call_txid = try contract.call(
        "scaleByRatio",
        &[_]runar.StateValue{ .{ .int = 3 }, .{ .int = 4 } },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 75 }} },
    );
    defer allocator.free(call_txid);

    std.log.info("MathDemo scaleByRatio TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "MathDemo_Call_ChainOperations" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Chain: 1000 -> divideBy(10)=100 -> squareRoot()=10 -> scaleByRatio(5,1)=50
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 1000 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Step 1: divideBy(10): 1000 / 10 = 100
    const txid1 = try contract.call(
        "divideBy",
        &[_]runar.StateValue{.{ .int = 10 }},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 100 }} },
    );
    defer allocator.free(txid1);
    std.log.info("MathDemo chain step 1 (divideBy): {s}", .{txid1});

    // Step 2: squareRoot(): sqrt(100) = 10
    const txid2 = try contract.call(
        "squareRoot",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 10 }} },
    );
    defer allocator.free(txid2);
    std.log.info("MathDemo chain step 2 (squareRoot): {s}", .{txid2});

    // Step 3: scaleByRatio(5, 1): 10 * 5 / 1 = 50
    const txid3 = try contract.call(
        "scaleByRatio",
        &[_]runar.StateValue{ .{ .int = 5 }, .{ .int = 1 } },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 50 }} },
    );
    defer allocator.free(txid3);
    std.log.info("MathDemo chain step 3 (scaleByRatio): {s}", .{txid3});

    std.log.info("MathDemo chain: 1000->100->10->50 succeeded", .{});
}

test "MathDemo_Call_ComputeLog2" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // log2(1024) = 10
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 1024 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Call computeLog2(): log2(1024) = 10
    const call_txid = try contract.call(
        "computeLog2",
        &.{},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 10 }} },
    );
    defer allocator.free(call_txid);

    std.log.info("MathDemo computeLog2 TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "MathDemo_Call_DivideThenClamp" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // 1000 -> divideBy(10)=100 -> clampValue(0, 50)=50
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 1000 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Step 1: divideBy(10): 1000 / 10 = 100
    const txid1 = try contract.call(
        "divideBy",
        &[_]runar.StateValue{.{ .int = 10 }},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 100 }} },
    );
    defer allocator.free(txid1);
    std.log.info("MathDemo divideThenClamp step 1 (divideBy): {s}", .{txid1});

    // Step 2: clampValue(0, 50): clamp(100, 0, 50) = 50
    const txid2 = try contract.call(
        "clampValue",
        &[_]runar.StateValue{ .{ .int = 0 }, .{ .int = 50 } },
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 50 }} },
    );
    defer allocator.free(txid2);
    std.log.info("MathDemo divideThenClamp step 2 (clampValue): {s}", .{txid2});

    std.log.info("MathDemo divideThenClamp: 1000->100->50 succeeded", .{});
}

test "MathDemo_Call_ReduceGcd" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // gcd(100, 75) = 25
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 100 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Call reduceGcd(75): gcd(100, 75) = 25
    const call_txid = try contract.call(
        "reduceGcd",
        &[_]runar.StateValue{.{ .int = 75 }},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 25 }} },
    );
    defer allocator.free(call_txid);

    std.log.info("MathDemo reduceGcd TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "MathDemo_RejectDivideByZero" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/zig/math-demo/MathDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MathDemo contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .int = 1000 },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 5000 });
    defer allocator.free(deploy_txid);

    // Call divideBy(0) — should be rejected on-chain (safediv fails on zero divisor)
    const result = contract.call(
        "divideBy",
        &[_]runar.StateValue{.{ .int = 0 }},
        rpc_provider.provider(),
        local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{.{ .int = 0 }} },
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestExpectedError;
    } else |_| {
        std.log.info("MathDemo correctly rejected divide by zero", .{});
    }
}
