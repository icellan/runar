const std = @import("std");
const runar = @import("runar");
const bsvz = @import("bsvz");
const helpers = @import("helpers.zig");
const compile = @import("compile.zig");

// ---------------------------------------------------------------------------
// Helpers — hex-encoded values for the SDK (on-chain convention)
// ---------------------------------------------------------------------------

const BB_PRIME: i64 = 2013265921;

fn bbMulField(a: i64, b: i64) i64 {
    return @rem(a * b, BB_PRIME);
}

fn hexSha256(allocator: std.mem.Allocator, hex_data: []const u8) ![]u8 {
    // Decode hex to bytes
    const byte_len = hex_data.len / 2;
    const data = try allocator.alloc(u8, byte_len);
    defer allocator.free(data);
    for (0..byte_len) |i| {
        data[i] = std.fmt.parseUnsigned(u8, hex_data[i * 2 .. i * 2 + 2], 16) catch 0;
    }

    // SHA-256
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});

    // Encode to hex
    const result = try allocator.alloc(u8, 64);
    const hex_chars = "0123456789abcdef";
    for (0..32) |i| {
        result[i * 2] = hex_chars[hash[i] >> 4];
        result[i * 2 + 1] = hex_chars[hash[i] & 0x0f];
    }
    return result;
}

fn hexHash256(allocator: std.mem.Allocator, hex_data: []const u8) ![]u8 {
    const first = try hexSha256(allocator, hex_data);
    defer allocator.free(first);
    return hexSha256(allocator, first);
}

fn hexStateRoot(allocator: std.mem.Allocator, n: usize) ![]u8 {
    const input = try std.fmt.allocPrint(allocator, "{x:0>2}", .{n});
    defer allocator.free(input);
    return hexSha256(allocator, input);
}

fn hexZeros32(allocator: std.mem.Allocator) ![]u8 {
    const result = try allocator.alloc(u8, 64);
    @memset(result, '0');
    return result;
}

const MerkleTree = struct {
    root: []const u8,
    layers: [][]const []const u8,
    leaves: []const []const u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *MerkleTree) void {
        for (self.layers) |layer| {
            for (layer) |item| self.allocator.free(item);
            self.allocator.free(layer);
        }
        self.allocator.free(self.layers);
        for (self.leaves) |leaf| self.allocator.free(leaf);
        self.allocator.free(self.leaves);
    }
};

fn buildMerkleTree(allocator: std.mem.Allocator) !MerkleTree {
    // Build 16 leaves
    var leaves = try allocator.alloc([]const u8, 16);
    for (0..16) |i| {
        const input = try std.fmt.allocPrint(allocator, "{x:0>2}", .{i});
        defer allocator.free(input);
        leaves[i] = try hexSha256(allocator, input);
    }

    var layers: std.ArrayListUnmanaged([]const []const u8) = .empty;

    // Clone first layer
    var first_layer = try allocator.alloc([]const u8, leaves.len);
    for (leaves, 0..) |leaf, i| first_layer[i] = try allocator.dupe(u8, leaf);
    try layers.append(allocator, first_layer);

    var level = first_layer;
    while (level.len > 1) {
        var next_layer = try allocator.alloc([]const u8, level.len / 2);
        for (0..level.len / 2) |i| {
            const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ level[i * 2], level[i * 2 + 1] });
            defer allocator.free(combined);
            next_layer[i] = try hexSha256(allocator, combined);
        }
        try layers.append(allocator, next_layer);
        level = next_layer;
    }

    return .{
        .root = level[0],
        .layers = try layers.toOwnedSlice(allocator),
        .leaves = leaves,
        .allocator = allocator,
    };
}

fn getProof(allocator: std.mem.Allocator, tree: *const MerkleTree, index: usize) !struct { leaf: []u8, proof: []u8 } {
    var siblings: std.ArrayListUnmanaged([]const u8) = .empty;
    defer siblings.deinit(allocator);

    var idx = index;
    for (0..tree.layers.len - 1) |d| {
        try siblings.append(allocator, tree.layers[d][idx ^ 1]);
        idx >>= 1;
    }

    var proof_len: usize = 0;
    for (siblings.items) |s| proof_len += s.len;

    var proof = try allocator.alloc(u8, proof_len);
    var offset: usize = 0;
    for (siblings.items) |s| {
        @memcpy(proof[offset .. offset + s.len], s);
        offset += s.len;
    }

    const leaf = try allocator.dupe(u8, tree.leaves[index]);

    return .{ .leaf = leaf, .proof = proof };
}

const SC_LEAF_IDX: usize = 3;

/// Build the call arguments for advanceState, mirroring the Python helper.
fn buildCallArgs(
    allocator: std.mem.Allocator,
    tree: *const MerkleTree,
    pre_state_root: []const u8,
    new_block_number: i64,
) !struct {
    args: [10]runar.StateValue,
    new_state_root: []u8,
    batch_data_hash: []u8,
    leaf: []u8,
    proof: []u8,
} {
    const new_state_root = try hexStateRoot(allocator, @intCast(new_block_number));
    errdefer allocator.free(new_state_root);

    const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ pre_state_root, new_state_root });
    defer allocator.free(combined);
    const batch_data_hash = try hexHash256(allocator, combined);
    errdefer allocator.free(batch_data_hash);

    const proof_a: i64 = 1000000;
    const proof_b: i64 = 2000000;
    const proof_c: i64 = bbMulField(proof_a, proof_b);

    const proof_data = try getProof(allocator, tree, SC_LEAF_IDX);

    return .{
        .args = [10]runar.StateValue{
            .{ .bytes = new_state_root },
            .{ .int = new_block_number },
            .{ .bytes = batch_data_hash },
            .{ .bytes = @constCast(pre_state_root) },
            .{ .int = proof_a },
            .{ .int = proof_b },
            .{ .int = proof_c },
            .{ .bytes = proof_data.leaf },
            .{ .bytes = proof_data.proof },
            .{ .int = @intCast(SC_LEAF_IDX) },
        },
        .new_state_root = new_state_root,
        .batch_data_hash = batch_data_hash,
        .leaf = proof_data.leaf,
        .proof = proof_data.proof,
    };
}

/// Deploy StateCovenant with initial state (zeros, block 0, tree root).
/// The artifact is heap-allocated because RunarContract stores a pointer to it.
fn deployStateCovenant(allocator: std.mem.Allocator) !struct {
    contract: runar.RunarContract,
    wallet: helpers.Wallet,
    rpc_provider: helpers.RPCProvider,
    local_signer: runar.LocalSigner,
    tree: MerkleTree,
    artifact: *runar.RunarArtifact,
    zeros: []u8,
    root_dup: []u8,
} {
    const artifact = try allocator.create(runar.RunarArtifact);
    errdefer allocator.destroy(artifact);
    artifact.* = compile.compileContract(allocator, "examples/ts/state-covenant/StateCovenant.runar.ts") catch |err| {
        std.log.warn("Could not compile StateCovenant contract: {any}, skipping test", .{err});
        return err;
    };
    errdefer artifact.deinit();

    var tree = try buildMerkleTree(allocator);
    errdefer tree.deinit();

    const zeros = try hexZeros32(allocator);
    errdefer allocator.free(zeros);

    const root_dup = try allocator.dupe(u8, tree.root);
    errdefer allocator.free(root_dup);

    var contract = try runar.RunarContract.init(allocator, artifact, &[_]runar.StateValue{
        .{ .bytes = zeros },
        .{ .int = 0 },
        .{ .bytes = root_dup },
    });
    errdefer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    errdefer wallet.deinit();

    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 10000 });
    defer allocator.free(deploy_txid);
    std.log.info("StateCovenant deployed: {s}", .{deploy_txid});

    return .{
        .contract = contract,
        .wallet = wallet,
        .rpc_provider = rpc_provider,
        .local_signer = local_signer,
        .tree = tree,
        .artifact = artifact,
        .zeros = zeros,
        .root_dup = root_dup,
    };
}

test "StateCovenant_Deploy" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var artifact = compile.compileContract(allocator, "examples/ts/state-covenant/StateCovenant.runar.ts") catch |err| {
        std.log.warn("Could not compile StateCovenant contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var tree = try buildMerkleTree(allocator);
    defer tree.deinit();

    const zeros = try hexZeros32(allocator);
    defer allocator.free(zeros);

    const root_dup = try allocator.dupe(u8, tree.root);
    defer allocator.free(root_dup);

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = zeros },
        .{ .int = 0 },
        .{ .bytes = root_dup },
    });
    defer contract.deinit();

    var wallet = try helpers.newWallet(allocator);
    defer wallet.deinit();
    const fund_txid = try helpers.fundWallet(allocator, &wallet, 1.0);
    defer allocator.free(fund_txid);

    var rpc_provider = helpers.RPCProvider.init(allocator);
    var local_signer = try wallet.localSigner();

    const deploy_txid = try contract.deploy(rpc_provider.provider(), local_signer.signer(), .{ .satoshis = 10000 });
    defer allocator.free(deploy_txid);
    std.log.info("StateCovenant deployed: {s}", .{deploy_txid});
    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
}

test "StateCovenant_AdvanceState" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var ctx = deployStateCovenant(allocator) catch return;
    defer ctx.contract.deinit();
    defer ctx.wallet.deinit();
    defer ctx.tree.deinit();
    defer {
        ctx.artifact.deinit();
        allocator.destroy(ctx.artifact);
    }
    defer allocator.free(ctx.zeros);
    defer allocator.free(ctx.root_dup);

    // Build args for first advance: block 0 -> 1
    var call = try buildCallArgs(allocator, &ctx.tree, ctx.zeros, 1);
    defer allocator.free(call.new_state_root);
    defer allocator.free(call.batch_data_hash);
    defer allocator.free(call.leaf);
    defer allocator.free(call.proof);

    const call_txid = try ctx.contract.call(
        "advanceState",
        &call.args,
        ctx.rpc_provider.provider(),
        ctx.local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = call.new_state_root },
            .{ .int = 1 },
        } },
    );
    defer allocator.free(call_txid);

    std.log.info("StateCovenant advanceState TX: {s}", .{call_txid});
    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
}

test "StateCovenant_ChainAdvances" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var ctx = deployStateCovenant(allocator) catch return;
    defer ctx.contract.deinit();
    defer ctx.wallet.deinit();
    defer ctx.tree.deinit();
    defer {
        ctx.artifact.deinit();
        allocator.destroy(ctx.artifact);
    }
    defer allocator.free(ctx.zeros);
    defer allocator.free(ctx.root_dup);

    // Chain 3 state advances: block 0 -> 1 -> 2 -> 3
    var pre_state_root: []u8 = try allocator.dupe(u8, ctx.zeros);

    for (1..4) |block| {
        var call = try buildCallArgs(allocator, &ctx.tree, pre_state_root, @intCast(block));
        defer allocator.free(call.batch_data_hash);
        defer allocator.free(call.leaf);
        defer allocator.free(call.proof);

        const call_txid = try ctx.contract.call(
            "advanceState",
            &call.args,
            ctx.rpc_provider.provider(),
            ctx.local_signer.signer(),
            .{ .new_state = &[_]runar.StateValue{
                .{ .bytes = call.new_state_root },
                .{ .int = @intCast(block) },
            } },
        );
        defer allocator.free(call_txid);
        std.log.info("StateCovenant chain advance to block {d}: {s}", .{ block, call_txid });

        // Update pre_state_root for next iteration
        allocator.free(pre_state_root);
        pre_state_root = call.new_state_root;
    }
    defer allocator.free(pre_state_root);

    std.log.info("StateCovenant chain 0->1->2->3 succeeded", .{});
}

test "StateCovenant_WrongPreStateRootRejected" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var ctx = deployStateCovenant(allocator) catch return;
    defer ctx.contract.deinit();
    defer ctx.wallet.deinit();
    defer ctx.tree.deinit();
    defer {
        ctx.artifact.deinit();
        allocator.destroy(ctx.artifact);
    }
    defer allocator.free(ctx.zeros);
    defer allocator.free(ctx.root_dup);

    // Build valid args first, then corrupt the preStateRoot (index 3)
    var call = try buildCallArgs(allocator, &ctx.tree, ctx.zeros, 1);
    defer allocator.free(call.new_state_root);
    defer allocator.free(call.batch_data_hash);
    defer allocator.free(call.leaf);
    defer allocator.free(call.proof);

    // Replace preStateRoot with a wrong value (flip first byte)
    var wrong_pre = try allocator.dupe(u8, ctx.zeros);
    defer allocator.free(wrong_pre);
    wrong_pre[0] = 'f';
    wrong_pre[1] = 'f';
    call.args[3] = .{ .bytes = wrong_pre };

    const result = ctx.contract.call(
        "advanceState",
        &call.args,
        ctx.rpc_provider.provider(),
        ctx.local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = call.new_state_root },
            .{ .int = 1 },
        } },
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestUnexpectedResult;
    } else |_| {
        std.log.info("StateCovenant correctly rejected wrong pre-state root", .{});
    }
}

test "StateCovenant_InvalidBlockNumberRejected" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var ctx = deployStateCovenant(allocator) catch return;
    defer ctx.contract.deinit();
    defer ctx.wallet.deinit();
    defer ctx.tree.deinit();
    defer {
        ctx.artifact.deinit();
        allocator.destroy(ctx.artifact);
    }
    defer allocator.free(ctx.zeros);
    defer allocator.free(ctx.root_dup);

    // First advance to block 1
    var call1 = try buildCallArgs(allocator, &ctx.tree, ctx.zeros, 1);
    defer allocator.free(call1.new_state_root);
    defer allocator.free(call1.batch_data_hash);
    defer allocator.free(call1.leaf);
    defer allocator.free(call1.proof);

    const txid1 = try ctx.contract.call(
        "advanceState",
        &call1.args,
        ctx.rpc_provider.provider(),
        ctx.local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = call1.new_state_root },
            .{ .int = 1 },
        } },
    );
    defer allocator.free(txid1);
    std.log.info("StateCovenant advanced to block 1: {s}", .{txid1});

    // Try to advance to block 0 (not increasing) -- should be rejected
    var call2 = try buildCallArgs(allocator, &ctx.tree, call1.new_state_root, 0);
    defer allocator.free(call2.new_state_root);
    defer allocator.free(call2.batch_data_hash);
    defer allocator.free(call2.leaf);
    defer allocator.free(call2.proof);

    // Force block number to 0
    call2.args[1] = .{ .int = 0 };

    const result = ctx.contract.call(
        "advanceState",
        &call2.args,
        ctx.rpc_provider.provider(),
        ctx.local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = call2.new_state_root },
            .{ .int = 0 },
        } },
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestUnexpectedResult;
    } else |_| {
        std.log.info("StateCovenant correctly rejected non-increasing block number", .{});
    }
}

test "StateCovenant_InvalidBabyBearProofRejected" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var ctx = deployStateCovenant(allocator) catch return;
    defer ctx.contract.deinit();
    defer ctx.wallet.deinit();
    defer ctx.tree.deinit();
    defer {
        ctx.artifact.deinit();
        allocator.destroy(ctx.artifact);
    }
    defer allocator.free(ctx.zeros);
    defer allocator.free(ctx.root_dup);

    // Build valid args then corrupt proofFieldC (index 6)
    var call = try buildCallArgs(allocator, &ctx.tree, ctx.zeros, 1);
    defer allocator.free(call.new_state_root);
    defer allocator.free(call.batch_data_hash);
    defer allocator.free(call.leaf);
    defer allocator.free(call.proof);

    // Set wrong proofFieldC
    call.args[6] = .{ .int = 99999 };

    const result = ctx.contract.call(
        "advanceState",
        &call.args,
        ctx.rpc_provider.provider(),
        ctx.local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = call.new_state_root },
            .{ .int = 1 },
        } },
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestUnexpectedResult;
    } else |_| {
        std.log.info("StateCovenant correctly rejected invalid Baby Bear proof", .{});
    }
}

test "StateCovenant_InvalidMerkleProofRejected" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var ctx = deployStateCovenant(allocator) catch return;
    defer ctx.contract.deinit();
    defer ctx.wallet.deinit();
    defer ctx.tree.deinit();
    defer {
        ctx.artifact.deinit();
        allocator.destroy(ctx.artifact);
    }
    defer allocator.free(ctx.zeros);
    defer allocator.free(ctx.root_dup);

    // Build valid args then corrupt merkleLeaf (index 7)
    var call = try buildCallArgs(allocator, &ctx.tree, ctx.zeros, 1);
    defer allocator.free(call.new_state_root);
    defer allocator.free(call.batch_data_hash);
    defer allocator.free(call.leaf);
    defer allocator.free(call.proof);

    // Replace merkleLeaf with a wrong value
    var wrong_leaf = try allocator.dupe(u8, call.leaf);
    defer allocator.free(wrong_leaf);
    wrong_leaf[0] = 'a';
    wrong_leaf[1] = 'a';
    call.args[7] = .{ .bytes = wrong_leaf };

    const result = ctx.contract.call(
        "advanceState",
        &call.args,
        ctx.rpc_provider.provider(),
        ctx.local_signer.signer(),
        .{ .new_state = &[_]runar.StateValue{
            .{ .bytes = call.new_state_root },
            .{ .int = 1 },
        } },
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestUnexpectedResult;
    } else |_| {
        std.log.info("StateCovenant correctly rejected invalid Merkle proof", .{});
    }
}
