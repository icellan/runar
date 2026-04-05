const std = @import("std");

const root = @import("../examples_test.zig");
const runar = @import("runar");
const MerkleProofDemo = @import("MerkleProofDemo.runar.zig").MerkleProofDemo;

fn contractPath(comptime basename: []const u8) []const u8 {
    return "merkle-proof/" ++ basename;
}

fn runCompileChecks(comptime basename: []const u8) !void {
    try root.runar.compileCheckSource(std.testing.allocator, @embedFile(basename), basename);
    try root.runar.compileCheckFile(std.testing.allocator, contractPath(basename));
}

test "compile-check MerkleProofDemo.runar.zig" {
    try runCompileChecks("MerkleProofDemo.runar.zig");
}

// Build a depth-4 SHA-256 Merkle tree from 16 leaves and verify proofs.
test "MerkleProofDemo verifySha256 accepts valid proof at index 0" {
    const leaves = buildLeaves();
    const tree = buildTree(leaves, sha256Fn);
    const proof_data = getProof(tree.layers, leaves, 0);

    const contract = MerkleProofDemo.init(tree.root);
    contract.verifySha256(leaves[0], proof_data.proof, 0);
}

test "MerkleProofDemo verifySha256 accepts valid proof at index 7" {
    const leaves = buildLeaves();
    const tree = buildTree(leaves, sha256Fn);
    const proof_data = getProof(tree.layers, leaves, 7);

    const contract = MerkleProofDemo.init(tree.root);
    contract.verifySha256(leaves[7], proof_data.proof, 7);
}

test "MerkleProofDemo verifyHash256 accepts valid proof at index 0" {
    const leaves = buildLeaves();
    const tree = buildTree(leaves, hash256Fn);
    const proof_data = getProof(tree.layers, leaves, 0);

    const contract = MerkleProofDemo.init(tree.root);
    contract.verifyHash256(leaves[0], proof_data.proof, 0);
}

// --- Helpers ---

fn sha256Fn(data: runar.ByteString) runar.ByteString {
    return runar.sha256(data);
}

fn hash256Fn(data: runar.ByteString) runar.ByteString {
    return runar.hash256(data);
}

const TreeResult = struct {
    root: runar.ByteString,
    layers: [5][16]runar.ByteString,
};

const ProofResult = struct {
    proof: runar.ByteString,
};

fn buildLeaves() [16]runar.ByteString {
    var leaves: [16]runar.ByteString = undefined;
    for (0..16) |i| {
        const byte = [1]u8{@intCast(i)};
        leaves[i] = runar.sha256(&byte);
    }
    return leaves;
}

fn buildTree(leaves: [16]runar.ByteString, hashFn: fn (runar.ByteString) runar.ByteString) TreeResult {
    var layers: [5][16]runar.ByteString = undefined;
    for (0..16) |i| {
        layers[0][i] = leaves[i];
    }

    var level_size: usize = 16;
    var level: usize = 0;
    while (level_size > 1) {
        const next_size = level_size / 2;
        for (0..next_size) |i| {
            layers[level + 1][i] = hashFn(runar.bytesConcat(layers[level][i * 2], layers[level][i * 2 + 1]));
        }
        level += 1;
        level_size = next_size;
    }

    return .{ .root = layers[4][0], .layers = layers };
}

fn getProof(layers: [5][16]runar.ByteString, leaves: [16]runar.ByteString, index: usize) ProofResult {
    _ = leaves;
    var siblings: [4]runar.ByteString = undefined;
    var idx = index;
    for (0..4) |d| {
        const sibling_idx = idx ^ 1;
        siblings[d] = layers[d][sibling_idx];
        idx = idx >> 1;
    }

    var proof = siblings[0];
    for (1..4) |i| {
        proof = runar.bytesConcat(proof, siblings[i]);
    }

    return .{ .proof = proof };
}
