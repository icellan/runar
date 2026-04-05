"""
Merkle proof verification integration tests -- inline contracts testing
merkleRootSha256 on a real regtest node.

Each test compiles a minimal stateless contract with an unrolled Merkle path
verification, deploys it on regtest, and spends via contract.call().
"""

import hashlib
import json
import os
import tempfile

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet,
)
from runar_compiler.compiler import compile_from_source, artifact_to_json
from runar.sdk import RunarArtifact, RunarContract, DeployOptions


# ---------------------------------------------------------------------------
# Merkle tree helpers
# ---------------------------------------------------------------------------

def sha256_hex(hex_str: str) -> str:
    data = bytes.fromhex(hex_str)
    return hashlib.sha256(data).hexdigest()


def build_sha256_tree(leaves: list[str]):
    level = list(leaves)
    layers = [level]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(sha256_hex(level[i] + level[i + 1]))
        level = next_level
        layers.append(level)
    return {"root": level[0], "leaves": leaves, "layers": layers}


def get_proof(tree: dict, index: int) -> tuple[str, str]:
    siblings = ""
    idx = index
    for d in range(len(tree["layers"]) - 1):
        siblings += tree["layers"][d][idx ^ 1]
        idx >>= 1
    return siblings, tree["leaves"][index]


# Build a depth-4 SHA-256 tree (16 leaves)
def build_test_tree():
    leaves = [sha256_hex(bytes([i]).hex()) for i in range(16)]
    return build_sha256_tree(leaves)


def _compile_source(source: str, file_name: str) -> RunarArtifact:
    """Compile inline source to an SDK artifact by writing a temp file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file_name, delete=False, dir=tempfile.gettempdir()
    ) as f:
        f.write(source)
        tmp_path = f.name
    try:
        compiler_artifact = compile_from_source(tmp_path)
        artifact_dict = json.loads(artifact_to_json(compiler_artifact))
        return RunarArtifact.from_dict(artifact_dict)
    finally:
        os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Contract source
# ---------------------------------------------------------------------------

MERKLE_SHA256_SOURCE = """\
import { SmartContract, assert, merkleRootSha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class MerkleSha256Test extends SmartContract {
  readonly expectedRoot: ByteString;
  constructor(expectedRoot: ByteString) {
    super(expectedRoot);
    this.expectedRoot = expectedRoot;
  }
  public verify(leaf: ByteString, proof: ByteString, index: bigint) {
    const root = merkleRootSha256(leaf, proof, index, 4n);
    assert(root === this.expectedRoot);
  }
}
"""


class TestMerkleProof:

    def test_merkle_sha256_leaf_index_0(self):
        """merkleRootSha256: verify leaf at index 0 (leftmost)."""
        tree = build_test_tree()
        proof, leaf = get_proof(tree, 0)

        artifact = _compile_source(MERKLE_SHA256_SOURCE, "MerkleSha256Test.runar.ts")
        assert artifact.contract_name == "MerkleSha256Test"

        contract = RunarContract(artifact, [tree["root"]])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

        call_txid, _ = contract.call("verify", [leaf, proof, 0], provider, wallet["signer"])
        assert call_txid

    def test_merkle_sha256_leaf_index_7(self):
        """merkleRootSha256: verify leaf at index 7 (middle)."""
        tree = build_test_tree()
        proof, leaf = get_proof(tree, 7)

        artifact = _compile_source(MERKLE_SHA256_SOURCE, "MerkleSha256Test.runar.ts")

        contract = RunarContract(artifact, [tree["root"]])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

        call_txid, _ = contract.call("verify", [leaf, proof, 7], provider, wallet["signer"])
        assert call_txid

    def test_merkle_sha256_wrong_leaf_rejected(self):
        """merkleRootSha256: wrong leaf rejected on-chain."""
        tree = build_test_tree()
        proof, _ = get_proof(tree, 0)
        wrong_leaf = sha256_hex("ff")

        artifact = _compile_source(MERKLE_SHA256_SOURCE, "MerkleSha256Test.runar.ts")

        contract = RunarContract(artifact, [tree["root"]])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call("verify", [wrong_leaf, proof, 0], provider, wallet["signer"])
