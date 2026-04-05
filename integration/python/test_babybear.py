"""
Baby Bear field arithmetic integration tests -- inline contracts testing
bbFieldAdd/bbFieldInv on a real regtest node.

Each test compiles a minimal stateless contract that exercises Baby Bear
built-ins, deploys it on regtest, and spends via contract.call().
"""

import json
import os
import tempfile

import pytest

from conftest import (
    compile_contract, create_provider, create_funded_wallet,
)
from runar_compiler.compiler import compile_from_source, artifact_to_json
from runar.sdk import RunarArtifact, RunarContract, DeployOptions


BB_P = 2013265921


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


class TestBabyBear:

    def test_bb_field_add(self):
        """bbFieldAdd: (3 + 7) mod p = 10."""
        source = """\
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddTest extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
"""
        artifact = _compile_source(source, "BBAddTest.runar.ts")
        assert artifact.contract_name == "BBAddTest"

        contract = RunarContract(artifact, [10])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

        call_txid, _ = contract.call("verify", [3, 7], provider, wallet["signer"])
        assert call_txid

    def test_bb_field_add_wrap_around(self):
        """bbFieldAdd: (p-1) + 1 = 0 mod p."""
        source = """\
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddWrap extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
"""
        artifact = _compile_source(source, "BBAddWrap.runar.ts")

        contract = RunarContract(artifact, [0])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))
        assert txid

        call_txid, _ = contract.call("verify", [BB_P - 1, 1], provider, wallet["signer"])
        assert call_txid

    def test_bb_field_inv_identity(self):
        """bbFieldInv: a * inv(a) = 1 (algebraic identity)."""
        source = """\
import { SmartContract, assert, bbFieldInv, bbFieldMul } from 'runar-lang';

class BBInvIdentity extends SmartContract {
  constructor() { super(); }
  public verify(a: bigint) {
    const inv = bbFieldInv(a);
    assert(bbFieldMul(a, inv) === 1n);
  }
}
"""
        artifact = _compile_source(source, "BBInvIdentity.runar.ts")
        assert artifact.contract_name == "BBInvIdentity"

        contract = RunarContract(artifact, [])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        txid, _ = contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=500000))
        assert txid

        call_txid, _ = contract.call("verify", [42], provider, wallet["signer"])
        assert call_txid

    def test_bb_field_add_wrong_result_rejected(self):
        """bbFieldAdd: wrong expected value rejected on-chain."""
        source = """\
import { SmartContract, assert, bbFieldAdd } from 'runar-lang';

class BBAddReject extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) { super(expected); this.expected = expected; }
  public verify(a: bigint, b: bigint) {
    assert(bbFieldAdd(a, b) === this.expected);
  }
}
"""
        artifact = _compile_source(source, "BBAddReject.runar.ts")
        # Wrong expected: 3+7=10, not 11
        contract = RunarContract(artifact, [11])

        provider = create_provider()
        wallet = create_funded_wallet(provider)

        contract.deploy(provider, wallet["signer"], DeployOptions(satoshis=5000))

        with pytest.raises(Exception):
            contract.call("verify", [3, 7], provider, wallet["signer"])
