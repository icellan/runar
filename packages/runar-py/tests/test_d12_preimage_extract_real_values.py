"""D12 D2: the SDK ANF interpreter answered ``extractLocktime`` /
``extractSequence`` / ``extractOutpoint`` with dummies (0 / 0xfffffffe / 36
zero bytes). A state field derived from one of them got a value the script
never computes, so the covenant refused the continuation. ``prepare_call`` now
hands the interpreter the real values of the transaction it builds.

Proves: with locktime 0 (sequence 0xffffffff) and with locktime 500 (sequence
0xfffffffe), the committed state equals the tx's own nLockTime / nSequence /
outpoint, and the validating MockProvider (bsv-sdk Spend) accepts the spend.
Does not prove: extra contract inputs (merge) -- only input 0 is modelled.
"""

from __future__ import annotations

import json

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.provider import MockProvider
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.local_signer import LocalSigner
from runar.sdk.types import RunarArtifact, DeployOptions, Utxo, CallOptions

from runar_compiler import compiler  # on sys.path via tests/conftest.py

SRC = '''import { StatefulSmartContract, ByteString, extractLocktime, extractSequence, extractOutpoint } from 'runar-lang';

class Probe extends StatefulSmartContract {
  lt: bigint;
  sq: bigint;
  op: ByteString;
  constructor(lt: bigint, sq: bigint, op: ByteString) { super(lt, sq, op); this.lt = lt; this.sq = sq; this.op = op; }
  public probe() {
    this.lt = extractLocktime(this.txPreimage);
    this.sq = extractSequence(this.txPreimage);
    this.op = extractOutpoint(this.txPreimage);
  }
}
'''


def _artifact() -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(SRC, "Probe.runar.ts")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


@pytest.mark.parametrize("locktime,want_seq", [(None, 0xFFFFFFFF), (500, 0xFFFFFFFE)])
def test_extractors_see_the_real_tx(locktime, want_seq):
    provider = MockProvider("testnet")
    signer = LocalSigner("11" * 32)
    provider.add_utxo(signer.get_address(), Utxo(
        txid="aa" * 32, output_index=0, satoshis=5_000_000,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    contract = RunarContract(_artifact(), [7, 7, "00"])
    contract.deploy(provider, signer, DeployOptions(satoshis=50_000))
    spent = contract.get_utxo()
    contract.call("probe", [], provider, signer, CallOptions(locktime=locktime))
    st = contract.get_state()
    assert st["lt"] == (locktime or 0)
    assert st["sq"] == want_seq
    assert st["op"] == bytes.fromhex(spent.txid)[::-1].hex() + spent.output_index.to_bytes(4, "little").hex()
