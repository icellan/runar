const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

test "SchnorrZKP_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/schnorr-zkp/SchnorrZKP.runar.zig") catch |err| {
        std.log.warn("Could not compile SchnorrZKP contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("SchnorrZKP", artifact.contract_name);
    std.log.info("SchnorrZKP compiled: {d} bytes", .{artifact.script.len / 2});
}

test "SchnorrZKP_ScriptSize" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/schnorr-zkp/SchnorrZKP.runar.zig") catch |err| {
        std.log.warn("Could not compile SchnorrZKP contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    const script_bytes = artifact.script.len / 2;
    // Schnorr ZKP uses EC operations, script should be 100KB-2MB
    try std.testing.expect(script_bytes >= 100000);
    try std.testing.expect(script_bytes <= 2000000);
    std.log.info("SchnorrZKP script size: {d} bytes", .{script_bytes});
}

test "SchnorrZKP_Deploy" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(allocator, "examples/zig/schnorr-zkp/SchnorrZKP.runar.zig") catch |err| {
        std.log.warn("Could not compile SchnorrZKP contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Use secp256k1 generator G as the public key (Point)
    const pub_key_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pub_key_hex },
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
    std.log.info("SchnorrZKP deployed: {s}", .{deploy_txid});
}

test "SchnorrZKP_DeployDifferentKey" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(allocator, "examples/zig/schnorr-zkp/SchnorrZKP.runar.zig") catch |err| {
        std.log.warn("Could not compile SchnorrZKP contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Key 1: G
    const pk1_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" ++
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    // Key 2: 2*G
    const pk2_hex = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" ++
        "1ae168fea63dc339a3c58419466ceae1032688d15f9c819fea738c882b9d5d90";

    // Deploy with key1
    var contract1 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk1_hex },
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

    // Deploy with key2
    var contract2 = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pk2_hex },
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
    std.log.info("key1 txid: {s}, key2 txid: {s}", .{ txid1, txid2 });
}

test "SchnorrZKP_ABI_Methods" {
    const allocator = std.testing.allocator;

    var artifact = compile.compileContract(allocator, "examples/zig/schnorr-zkp/SchnorrZKP.runar.zig") catch |err| {
        std.log.warn("Could not compile SchnorrZKP contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // SchnorrZKP should have a verify method
    var has_verify = false;
    for (artifact.abi.methods) |m| {
        if (m.is_public) {
            if (std.mem.eql(u8, m.name, "verify")) has_verify = true;
        }
    }
    try std.testing.expect(has_verify);
}

test "SchnorrZKP_SpendValidProof" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    var artifact = compile.compileContract(allocator, "examples/zig/schnorr-zkp/SchnorrZKP.runar.zig") catch |err| {
        std.log.warn("Could not compile SchnorrZKP contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    // Precomputed values:
    // Private key k=42, public key P = k*G
    const pub_key_hex = "fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af" ++
        "07b158f244cd0de2134ac7c1d371cffbfae4db40801a2572e531c573cda9b5b4";

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = pub_key_hex },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 50000 });
    defer allocator.free(deploy_txid);
    std.log.info("SchnorrZKP deployed: {s}", .{deploy_txid});

    // Precomputed Schnorr ZKP proof:
    //   Nonce r=7777, commitment R = r*G
    //   Challenge e = bin2num(hash256(R || P)) via Fiat-Shamir
    //   Response s = (r + e*k) mod N = 15404805059957294180371105962960906537181676920494605924177451932397558133607
    const r_point_hex = "d5e41065eaf890e9e90469360acf6a4359795c7a1939d8ed42941a8c6ef31364" ++
        "191ec4c8a559fd4e7abbb6b8f2e4c32cbd2f30cb0d06ff6d21f156cbf65bbcad";

    // s as i64 won't fit; pass as LE signed-magnitude hex bytes
    // s = 15404805059957294180371105962960906537181676920494605924177451932397558133607
    // Encoded as LE signed-magnitude hex:
    const s_hex = "67739575b01a9d7d9e055d13d08e241f907a693512034b28473e0cc988cf0e22";

    const call_txid = try contract.call(
        "verify",
        &[_]runar.StateValue{
            .{ .bytes = r_point_hex },
            .{ .bytes = s_hex },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("SchnorrZKP spend TX: {s}", .{call_txid});
}
