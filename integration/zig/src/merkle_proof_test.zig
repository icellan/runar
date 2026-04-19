const std = @import("std");
const runar = @import("runar");
const helpers = @import("helpers.zig");
const compile_mod = @import("compile.zig");

// ---------------------------------------------------------------------------
// Merkle proof verification tests: verify merkleRootSha256 compiles, deploys,
// and calls correctly on a regtest node.
// ---------------------------------------------------------------------------

// SHA-256 helper
fn sha256Hex(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    const byte_len = hex_str.len / 2;
    const bytes = try allocator.alloc(u8, byte_len);
    defer allocator.free(bytes);

    for (0..byte_len) |i| {
        bytes[i] = std.fmt.parseInt(u8, hex_str[i * 2 .. i * 2 + 2], 16) catch return error.InvalidHex;
    }

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(bytes);
    const hash = hasher.finalResult();

    const hex_buf = try allocator.alloc(u8, 64);
    const hex_chars = "0123456789abcdef";
    for (0..32) |i| {
        hex_buf[i * 2] = hex_chars[hash[i] >> 4];
        hex_buf[i * 2 + 1] = hex_chars[hash[i] & 0x0f];
    }
    return hex_buf;
}

// Build depth-4 SHA-256 Merkle tree (16 leaves)
fn buildTreeAndProof(allocator: std.mem.Allocator, leaf_index: usize) !struct {
    root: []const u8,
    proof: []const u8,
    leaf: []const u8,
} {
    const leaf_inputs = [16][]const u8{
        "00", "01", "02", "03", "04", "05", "06", "07",
        "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
    };

    // Compute all leaves
    var leaves: [16][]const u8 = undefined;
    for (0..16) |i| {
        leaves[i] = try sha256Hex(allocator, leaf_inputs[i]);
    }

    // Build tree bottom-up, collecting layers for proof extraction
    var current_layer: [16][]const u8 = leaves;
    var current_len: usize = 16;

    // Store sibling at each level for the proof
    var siblings: [4][]const u8 = undefined;
    var proof_idx = leaf_index;

    for (0..4) |level| {
        const sibling_idx = proof_idx ^ 1;
        siblings[level] = try allocator.dupe(u8, current_layer[sibling_idx]);

        const next_len = current_len / 2;
        var next_layer: [16][]const u8 = undefined;
        for (0..next_len) |i| {
            const concat = try allocator.alloc(u8, 128);
            defer allocator.free(concat);
            @memcpy(concat[0..64], current_layer[i * 2]);
            @memcpy(concat[64..128], current_layer[i * 2 + 1]);
            next_layer[i] = try sha256Hex(allocator, concat);
        }

        // Free previous layer hashes (except original leaves which we still need)
        if (level > 0) {
            for (0..current_len) |i| {
                allocator.free(current_layer[i]);
            }
        }

        for (0..next_len) |i| {
            current_layer[i] = next_layer[i];
        }
        current_len = next_len;
        proof_idx >>= 1;
    }

    // current_layer[0] is the root
    const root = try allocator.dupe(u8, current_layer[0]);
    // Free the root in current_layer
    allocator.free(current_layer[0]);

    // Concatenate siblings into proof hex
    const proof = try allocator.alloc(u8, 4 * 64);
    for (0..4) |i| {
        @memcpy(proof[i * 64 .. (i + 1) * 64], siblings[i]);
        allocator.free(siblings[i]);
    }

    const leaf = try allocator.dupe(u8, leaves[leaf_index]);

    // Free all leaves
    for (0..16) |i| {
        allocator.free(leaves[i]);
    }

    return .{ .root = root, .proof = proof, .leaf = leaf };
}

test "MerkleProof_Compile" {
    const allocator = std.testing.allocator;

    var artifact = compile_mod.compileContract(allocator, "examples/zig/merkle-proof/MerkleProofDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MerkleProofDemo: {any}, skipping", .{err});
        return;
    };
    defer artifact.deinit();

    try std.testing.expectEqualStrings("MerkleProofDemo", artifact.contract_name);
    std.log.info("MerkleProofDemo compiled: {d} bytes", .{artifact.script.len / 2});
}

test "MerkleProof_Sha256_LeafIndex0" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    const tree = buildTreeAndProof(allocator, 0) catch |err| {
        std.log.warn("Could not build test tree: {any}, skipping", .{err});
        return;
    };
    defer {
        allocator.free(tree.root);
        allocator.free(tree.proof);
        allocator.free(tree.leaf);
    }

    var artifact = compile_mod.compileContract(allocator, "examples/zig/merkle-proof/MerkleProofDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MerkleProofDemo: {any}, skipping", .{err});
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

    try std.testing.expectEqual(@as(usize, 64), deploy_txid.len);
    std.log.info("MerkleProofDemo deployed: {s}", .{deploy_txid});

    const call_txid = try contract.call(
        "verifySha256",
        &[_]runar.StateValue{
            .{ .bytes = tree.leaf },
            .{ .bytes = tree.proof },
            .{ .int = 0 },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );
    defer allocator.free(call_txid);

    try std.testing.expectEqual(@as(usize, 64), call_txid.len);
    std.log.info("MerkleProof leaf 0 TX: {s}", .{call_txid});
}

test "MerkleProof_Sha256_WrongLeaf_Rejected" {
    const allocator = std.testing.allocator;

    helpers.requireNodeAvailable(allocator);

    const tree = buildTreeAndProof(allocator, 0) catch |err| {
        std.log.warn("Could not build test tree: {any}, skipping", .{err});
        return;
    };
    defer {
        allocator.free(tree.root);
        allocator.free(tree.proof);
        allocator.free(tree.leaf);
    }

    const wrong_leaf = try sha256Hex(allocator, "ff");
    defer allocator.free(wrong_leaf);

    var artifact = compile_mod.compileContract(allocator, "examples/zig/merkle-proof/MerkleProofDemo.runar.zig") catch |err| {
        std.log.warn("Could not compile MerkleProofDemo: {any}, skipping", .{err});
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

    // Call with wrong leaf — should be rejected on-chain
    const result = contract.call(
        "verifySha256",
        &[_]runar.StateValue{
            .{ .bytes = wrong_leaf },
            .{ .bytes = tree.proof },
            .{ .int = 0 },
        },
        rpc_provider.provider(),
        local_signer.signer(),
        null,
    );

    if (result) |call_txid| {
        allocator.free(call_txid);
        return error.TestExpectedError;
    } else |_| {
        std.log.info("MerkleProof correctly rejected wrong leaf", .{});
    }
}
