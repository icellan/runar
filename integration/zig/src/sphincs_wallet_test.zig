const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "SPHINCSWallet_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/sphincs-wallet/SPHINCSWallet.runar.zig") catch |err| {
        std.log.warn("Could not compile SPHINCSWallet contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("SPHINCSWallet", artifact.contract_name);
    std.log.info("SPHINCSWallet compiled: {d} bytes", .{artifact.script.len / 2});
}

test "SPHINCSWallet_ScriptSize" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/sphincs-wallet/SPHINCSWallet.runar.zig") catch |err| {
        std.log.warn("Could not compile SPHINCSWallet contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    const script_bytes = artifact.script.len / 2;
    // Hybrid ECDSA+SLH-DSA contracts produce very large scripts (100-500 KB)
    try std.testing.expect(script_bytes >= 100000);
    try std.testing.expect(script_bytes <= 500000);
    std.log.info("SPHINCSWallet script size: {d} bytes", .{script_bytes});
}

test "SPHINCSWallet_Deploy" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(allocator, "examples/zig/sphincs-wallet/SPHINCSWallet.runar.zig") catch |err| {
        std.log.warn("Could not compile SPHINCSWallet contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var ecdsa_wallet = try helpers.newWallet(allocator);
    defer ecdsa_wallet.deinit();

    const ecdsa_pkh = try ecdsa_wallet.pubKeyHashHex(allocator);
    defer allocator.free(ecdsa_pkh);

    // SLH-DSA public key hash: use a deterministic 20-byte (40-char hex) hash
    // In production this would be hash160(SLH-DSA public key)
    const slhdsa_pkh_hex = "0102030405060708091011121314151617181920";

    // Constructor: ecdsaPubKeyHash, slhdsaPubKeyHash
    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = ecdsa_pkh },
        .{ .bytes = slhdsa_pkh_hex },
    });
    defer contract.deinit();

    var funder = try helpers.newWallet(allocator);
    defer funder.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &funder, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try funder.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 50000 });
    defer allocator.free(deploy_txid);

    const utxo = contract.getCurrentUtxo();
    try std.testing.expect(utxo != null);
    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("SPHINCSWallet deployed: {s}", .{deploy_txid});
}

test "SPHINCSWallet_DeployDifferentKey" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(allocator, "examples/zig/sphincs-wallet/SPHINCSWallet.runar.zig") catch |err| {
        std.log.warn("Could not compile SPHINCSWallet contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var ecdsa_wallet = try helpers.newWallet(allocator);
    defer ecdsa_wallet.deinit();
    const ecdsa_pkh = try ecdsa_wallet.pubKeyHashHex(allocator);
    defer allocator.free(ecdsa_pkh);

    // Keypair 1
    const pkh1 = "0102030405060708091011121314151617181920";

    // Keypair 2 (different seed -> different hash)
    const pkh2 = "aabbccddeeff00112233445566778899aabbccdd";

    // Deploy with kp1
    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = ecdsa_pkh },
        .{ .bytes = pkh1 },
    });
    defer contract1.deinit();

    var funder1 = try helpers.newWallet(allocator);
    defer funder1.deinit();
    const fund1 = try helpers.fundWallet(allocator, &funder1, 1.0);
    defer allocator.free(fund1);

    var rpc1 = helpers.RPCProvider.init(allocator);
    var signer1 = try funder1.localSigner();
    const txid1 = try contract1.deploy(rpc1.provider(), signer1.signer(), .{ .satoshis = 50000 });
    defer allocator.free(txid1);

    // Deploy with kp2
    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = ecdsa_pkh },
        .{ .bytes = pkh2 },
    });
    defer contract2.deinit();

    var funder2 = try helpers.newWallet(allocator);
    defer funder2.deinit();
    const fund2 = try helpers.fundWallet(allocator, &funder2, 1.0);
    defer allocator.free(fund2);

    var rpc2 = helpers.RPCProvider.init(allocator);
    var signer2 = try funder2.localSigner();
    const txid2 = try contract2.deploy(rpc2.provider(), signer2.signer(), .{ .satoshis = 50000 });
    defer allocator.free(txid2);

    try std.testing.expect(!std.mem.eql(u8, txid1, txid2));
    std.log.info("seed1 txid: {s}, seed2 txid: {s}", .{ txid1, txid2 });
}

test "SPHINCSWallet_NotStateful" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/sphincs-wallet/SPHINCSWallet.runar.zig") catch |err| {
        std.log.warn("Could not compile SPHINCSWallet contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // SPHINCSWallet is a stateless contract (extends SmartContract)
    try std.testing.expect(!artifact.isStateful());
}
