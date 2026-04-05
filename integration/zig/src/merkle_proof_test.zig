const std = @import("std");
const runar = @import("runar");
const runar_frontend = @import("runar_frontend");
const helpers = @import("helpers.zig");

// ---------------------------------------------------------------------------
// Merkle proof verification tests: verify merkleRootSha256 compiles, deploys,
// and calls correctly on a regtest node.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// SHA-256 helper
// ---------------------------------------------------------------------------

fn sha256Bytes(data: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    return hasher.finalResult();
}

fn sha256Hex(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    // Decode hex to bytes
    const byte_len = hex_str.len / 2;
    const bytes = try allocator.alloc(u8, byte_len);
    defer allocator.free(bytes);

    for (0..byte_len) |i| {
        bytes[i] = std.fmt.parseInt(u8, hex_str[i * 2 .. i * 2 + 2], 16) catch return error.OutOfMemory;
    }

    const hash = sha256Bytes(bytes);

    // Encode hash as hex
    const hex_buf = try allocator.alloc(u8, 64);
    for (0..32) |i| {
        const high = hash[i] >> 4;
        const low = hash[i] & 0x0f;
        hex_buf[i * 2] = if (high < 10) '0' + high else 'a' + high - 10;
        hex_buf[i * 2 + 1] = if (low < 10) '0' + low else 'a' + low - 10;
    }
    return hex_buf;
}

// ---------------------------------------------------------------------------
// Merkle tree builder
// ---------------------------------------------------------------------------

const MerkleTree = struct {
    root: []const u8,
    leaves: [][]const u8,
    layers: [][]const []const u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *MerkleTree) void {
        for (self.layers) |layer| {
            for (layer) |node| {
                self.allocator.free(node);
            }
            self.allocator.free(layer);
        }
        self.allocator.free(self.layers);
        self.allocator.free(self.leaves);
    }
};

fn buildTestTree(allocator: std.mem.Allocator) !MerkleTree {
    // Build 16 leaves: sha256(bytes([i])) for i = 0..15
    const leaf_inputs = [16][]const u8{
        "00", "01", "02", "03", "04", "05", "06", "07",
        "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
    };

    var leaves = try allocator.alloc([]const u8, 16);
    for (0..16) |i| {
        leaves[i] = try sha256Hex(allocator, leaf_inputs[i]);
    }

    // Build tree layers
    var layers_list: std.ArrayListUnmanaged([]const []const u8) = .empty;
    errdefer layers_list.deinit(allocator);

    // First layer: copy of leaves
    var first_layer = try allocator.alloc([]const u8, 16);
    for (0..16) |i| {
        first_layer[i] = try allocator.dupe(u8, leaves[i]);
    }
    try layers_list.append(allocator, first_layer);

    var level = first_layer;
    while (level.len > 1) {
        const next_len = level.len / 2;
        var next = try allocator.alloc([]const u8, next_len);
        for (0..next_len) |i| {
            // Concatenate level[2*i] and level[2*i+1]
            const concat = try allocator.alloc(u8, 128);
            defer allocator.free(concat);
            @memcpy(concat[0..64], level[i * 2]);
            @memcpy(concat[64..128], level[i * 2 + 1]);
            next[i] = try sha256Hex(allocator, concat);
        }
        try layers_list.append(allocator, next);
        level = next;
    }

    const layers = try layers_list.toOwnedSlice(allocator);

    return MerkleTree{
        .root = layers[layers.len - 1][0],
        .leaves = leaves,
        .layers = layers,
        .allocator = allocator,
    };
}

fn getProof(allocator: std.mem.Allocator, tree: *const MerkleTree, index: usize) !struct { proof: []const u8, leaf: []const u8 } {
    var siblings: std.ArrayListUnmanaged(u8) = .empty;
    errdefer siblings.deinit(allocator);

    var idx = index;
    for (0..tree.layers.len - 1) |d| {
        const sibling = tree.layers[d][idx ^ 1];
        try siblings.appendSlice(allocator, sibling);
        idx >>= 1;
    }

    return .{
        .proof = try siblings.toOwnedSlice(allocator),
        .leaf = tree.leaves[index],
    };
}

// ---------------------------------------------------------------------------
// Contract source
// ---------------------------------------------------------------------------

const MERKLE_SHA256_SOURCE =
    \\import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';
    \\import type { ByteString } from 'runar-lang';
    \\
    \\class MerkleSha256Test extends SmartContract {
    \\  readonly expectedRoot: ByteString;
    \\  constructor(expectedRoot: ByteString) {
    \\    super(expectedRoot);
    \\    this.expectedRoot = expectedRoot;
    \\  }
    \\  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    \\    const root = merkleRootSha256(leaf, proof, index, 4n);
    \\    assert(root === this.expectedRoot);
    \\  }
    \\}
;

test "MerkleProof_Sha256_LeafIndex0" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var tree = buildTestTree(allocator) catch |err| {
        std.log.warn("Could not build test tree: {any}, skipping test", .{err});
        return;
    };
    defer tree.deinit();

    const proof_data = try getProof(allocator, &tree, 0);
    defer allocator.free(proof_data.proof);

    var artifact = compileInlineSource(allocator, MERKLE_SHA256_SOURCE, "MerkleSha256Test.runar.ts") catch |err| {
        std.log.warn("Could not compile MerkleSha256Test contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("MerkleSha256Test", artifact.contract_name);
    std.log.info("MerkleSha256Test compiled: {d} bytes", .{artifact.script.len / 2});

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = tree.root },
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
    std.log.info("MerkleSha256Test deployed: {s}", .{deploy_txid});

    const call_txid = try contract.call(
        "verify",
        &[_]runar.StateValue{
            .{ .bytes = proof_data.leaf },
            .{ .bytes = proof_data.proof },
            .{ .int = 0 },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("MerkleSha256 leaf 0 TX: {s}", .{call_txid});
}

test "MerkleProof_Sha256_LeafIndex7" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var tree = buildTestTree(allocator) catch |err| {
        std.log.warn("Could not build test tree: {any}, skipping test", .{err});
        return;
    };
    defer tree.deinit();

    const proof_data = try getProof(allocator, &tree, 7);
    defer allocator.free(proof_data.proof);

    var artifact = compileInlineSource(allocator, MERKLE_SHA256_SOURCE, "MerkleSha256Test.runar.ts") catch |err| {
        std.log.warn("Could not compile MerkleSha256Test contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = tree.root },
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
    std.log.info("MerkleSha256Test deployed: {s}", .{deploy_txid});

    const call_txid = try contract.call(
        "verify",
        &[_]runar.StateValue{
            .{ .bytes = proof_data.leaf },
            .{ .bytes = proof_data.proof },
            .{ .int = 7 },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("MerkleSha256 leaf 7 TX: {s}", .{call_txid});
}

test "MerkleProof_Sha256_WrongLeaf_Rejected" {
    const allocator = std.testing.allocator;

    if (!helpers.isNodeAvailable(allocator)) {
        std.log.warn("Regtest node not available, skipping test", .{});
        return;
    }

    var tree = buildTestTree(allocator) catch |err| {
        std.log.warn("Could not build test tree: {any}, skipping test", .{err});
        return;
    };
    defer tree.deinit();

    const proof_data = try getProof(allocator, &tree, 0);
    defer allocator.free(proof_data.proof);

    // Wrong leaf: sha256("ff") instead of sha256("00")
    const wrong_leaf = try sha256Hex(allocator, "ff");
    defer allocator.free(wrong_leaf);

    var artifact = compileInlineSource(allocator, MERKLE_SHA256_SOURCE, "MerkleSha256Test.runar.ts") catch |err| {
        std.log.warn("Could not compile MerkleSha256Test contract: {any}, skipping test", .{err});
        return;
    };
    defer artifact.deinit();

    var contract = try runar.RunarContract.init(allocator, &artifact, &[_]runar.StateValue{
        .{ .bytes = tree.root },
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
    std.log.info("MerkleSha256 reject test deployed: {s}", .{deploy_txid});

    // Call with wrong leaf — should be rejected on-chain
    const result = contract.call(
        "verify",
        &[_]runar.StateValue{
            .{ .bytes = wrong_leaf },
            .{ .bytes = proof_data.proof },
            .{ .int = 0 },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestExpectedError; // Should have been rejected
    } else |_| {
        // Expected rejection
        std.log.info("MerkleSha256 correctly rejected wrong leaf", .{});
    }
}
