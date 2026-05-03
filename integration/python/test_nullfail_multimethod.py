"""
NULLFAIL reproduction test -- multi-method stateful contract where some
methods use ``checkSig`` and others don't.

This is the BSV NULLFAIL rule (BIP 146) regression-guard from
``integration/ts/nullfail-multimethod.test.ts``: after a chain of UTXO
spends through the non-checkSig method, the transaction must not be
rejected with "Signature must be zero for failed CHECK(MULTI)SIG
operation". This module satisfies the per-case Python gap.
"""

import json
import os
import tempfile

import pytest

from conftest import compile_contract, create_provider, create_funded_wallet
from runar_compiler.compiler import compile_from_source, artifact_to_json
from runar.sdk import RunarArtifact, RunarContract, DeployOptions


MULTI_METHOD_SOURCE = """\
import {
  StatefulSmartContract, assert, checkSig,
} from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class MultiMethodContract extends StatefulSmartContract {
  stateRoot: ByteString;
  blockNumber: bigint;
  frozen: bigint;
  readonly governanceKey: PubKey;

  constructor(stateRoot: ByteString, blockNumber: bigint, frozen: bigint, governanceKey: PubKey) {
    super(stateRoot, blockNumber, frozen, governanceKey);
    this.stateRoot = stateRoot;
    this.blockNumber = blockNumber;
    this.frozen = frozen;
    this.governanceKey = governanceKey;
  }

  // Method 0: no checkSig -- authorized by proof data only.
  public advanceState(newStateRoot: ByteString, newBlockNumber: bigint) {
    assert(this.frozen === 0n);
    assert(newBlockNumber > this.blockNumber);
    this.stateRoot = newStateRoot;
    this.blockNumber = newBlockNumber;
  }

  // Method 1: uses checkSig -- governance action.
  public freeze(sig: Sig) {
    assert(checkSig(sig, this.governanceKey));
    this.frozen = 1n;
  }
}
"""


def _compile_source(source: str, file_name: str) -> RunarArtifact:
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


class TestNullFailMultiMethod:

    def test_compile(self):
        artifact = _compile_source(MULTI_METHOD_SOURCE, "MultiMethodContract.runar.ts")
        assert artifact
        assert artifact.contract_name == "MultiMethodContract"

    def test_chain_advance_state_does_not_trigger_nullfail(self):
        """Three consecutive ``advanceState`` (non-checkSig) calls must each
        succeed. A regression in the per-method script-path selection would
        manifest as "Signature must be zero for failed CHECK(MULTI)SIG
        operation" on the second or third spend."""
        artifact = _compile_source(MULTI_METHOD_SOURCE, "MultiMethodContract.runar.ts")
        provider = create_provider()
        wallet = create_funded_wallet(provider)

        zero_root = "00" * 32
        contract = RunarContract(
            artifact, [zero_root, 0, 0, wallet["pubKeyHex"]],
        )
        contract.deploy(
            provider, wallet["signer"], DeployOptions(satoshis=10_000),
        )

        # Three chained advanceState calls -- each picks the non-checkSig
        # branch of the multi-method dispatch.
        for i in range(1, 4):
            new_root = bytes([i]) * 32
            txid, _ = contract.call(
                "advanceState",
                [new_root.hex(), i],
                provider, wallet["signer"],
            )
            assert txid, f"advanceState[{i}] failed"
            assert len(txid) == 64
