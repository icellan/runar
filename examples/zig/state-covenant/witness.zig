//! F-168: shared witness data for `StateCovenant.advanceState`, used by both
//! StateCovenant_test.zig (the happy path and the "init stores constructor
//! arguments" check, run in-process) and assert_probe.zig (the five
//! invalid-input probes, run out-of-process because a native Rúnar assert
//! failure is a panic — see assert_probe.zig's doc comment).
//!
//! `valid()` returns a fully self-consistent set of inputs: every one of
//! `advanceState`'s five assertions passes against it. Each probe takes this
//! baseline and corrupts exactly one field, so the resulting panic is
//! attributable to exactly the assertion under test.

const runar = @import("runar");

pub const Witness = struct {
    preStateRoot: runar.ByteString,
    newStateRoot: runar.ByteString,
    newBlockNumber: i64,
    verifyingKeyHash: runar.ByteString,
    batchDataHash: runar.ByteString,
    proofFieldA: i64,
    proofFieldB: i64,
    proofFieldC: i64,
    merkleLeaf: runar.ByteString,
    merkleProof: runar.ByteString,
    merkleIndex: i64,
};

pub fn valid() Witness {
    const preStateRoot = "aa" ** 32;
    const newStateRoot = "bb" ** 32;
    const merkleLeaf = "cc" ** 32;
    // Depth-4 SHA-256 Merkle proof: four 32-byte siblings, one per layer.
    const merkleProof = ("d" ** 32) ++ ("e" ** 32) ++ ("f" ** 32) ++ ("g" ** 32);
    const merkleIndex: i64 = 5; // arbitrary path through the 4-bit index

    return .{
        .preStateRoot = preStateRoot,
        .newStateRoot = newStateRoot,
        .newBlockNumber = 1,
        // The expected Merkle root IS whatever merkleRootSha256 computes for
        // (merkleLeaf, merkleProof, merkleIndex) — the siblings don't need to
        // come from a real tree, only to be consistent with the root we
        // commit to as verifyingKeyHash.
        .verifyingKeyHash = runar.merkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 4),
        .batchDataHash = runar.hash256(runar.cat(preStateRoot, newStateRoot)),
        .proofFieldA = 6,
        .proofFieldB = 7,
        .proofFieldC = 42, // bbFieldMul(6, 7) == 42
        .merkleLeaf = merkleLeaf,
        .merkleProof = merkleProof,
        .merkleIndex = merkleIndex,
    };
}
