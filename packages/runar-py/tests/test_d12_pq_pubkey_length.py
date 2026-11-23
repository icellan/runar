"""D12 PQ-F1: a wrong-length WOTS+ / SLH-DSA public key deployed silently and
the output refused the owner's valid signature forever (the compiled verifier
splits the key at fixed offsets). ``RunarContract`` now refuses, at
construction, a constructor arg that flows straight (as a property load) into
the pk operand of ``verifyWOTS`` (64 bytes) or ``verifySLHDSA_SHA2_*`` (2n:
32 / 48 / 64 bytes).

Proves: wrong lengths are refused and the right length is accepted for WOTS
and every SLH-DSA parameter set, on artifacts that carry ANF (stateful).
Does not prove: stateless artifacts (they ship no ANF, so the SDK cannot see
the data flow), hash-committed keys, or keys passed as method args.
"""

from __future__ import annotations

import json

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.types import RunarArtifact

from runar_compiler import compiler  # on sys.path via tests/conftest.py


def _artifact(verify: str) -> RunarArtifact:
    src = f'''import {{ StatefulSmartContract, ByteString, assert, {verify} }} from 'runar-lang';

class Pq extends StatefulSmartContract {{
  readonly pk: ByteString;
  n: bigint;
  constructor(pk: ByteString, n: bigint) {{ super(pk, n); this.pk = pk; this.n = n; }}
  public spend(msg: ByteString, sig: ByteString) {{
    assert({verify}(msg, sig, this.pk));
    this.n = this.n + 1n;
  }}
}}
'''
    result = compiler.compile_from_source_str_with_result(src, "Pq.runar.ts")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


_CASES = [
    ("verifyWOTS", 64),
    ("verifySLHDSA_SHA2_128s", 32),
    ("verifySLHDSA_SHA2_128f", 32),
    ("verifySLHDSA_SHA2_192s", 48),
    ("verifySLHDSA_SHA2_192f", 48),
    ("verifySLHDSA_SHA2_256s", 64),
    ("verifySLHDSA_SHA2_256f", 64),
]


@pytest.mark.parametrize("verify,want", _CASES)
def test_pq_pubkey_length_enforced(verify, want):
    art = _artifact(verify)
    RunarContract(art, ["ab" * want, 0])
    for bad in (0, want - 1, want + 1, want // 2, want * 2):
        with pytest.raises(ValueError, match="public key"):
            RunarContract(art, ["ab" * bad, 0])


# PQ-F1 (artifact field): the check reads ``pqPubKeyParams``, so a STATELESS
# artifact (no ANF) is refused too, with the message shared by all seven SDKs;
# an older stateful artifact without the field falls back to the ANF walk.

_STATELESS = '''import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class SW extends SmartContract {
  readonly pk: ByteString;
  constructor(pk: ByteString) { super(pk); this.pk = pk; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); }
}
'''

_LEGACY = '''import { StatefulSmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class LW extends StatefulSmartContract {
  readonly pk: ByteString;
  n: bigint;
  constructor(pk: ByteString, n: bigint) { super(pk, n); this.pk = pk; this.n = n; }
  public spend(msg: ByteString, sig: ByteString) { const k = this.pk; assert(verifyWOTS(msg, sig, k)); this.n = this.n + 1n; }
}
'''


def _artifact_dict(src: str, name: str) -> dict:
    result = compiler.compile_from_source_str_with_result(src, name)
    assert result.artifact is not None, [d.message for d in result.diagnostics]
    return json.loads(compiler.artifact_to_json(result.artifact))


def test_pq_f1_stateless_artifact_refused_with_shared_message():
    d = _artifact_dict(_STATELESS, "SW.runar.ts")
    assert "anf" not in d
    art = RunarArtifact.from_dict(d)
    want = (
        "RunarContract: constructor arg 'pk' is the verifyWOTS public key and must be exactly 64 bytes, got 32. "
        "A locking script built from it would refuse every valid signature, so the output could never be spent (PQ-F1)"
    )
    with pytest.raises(ValueError) as e:
        RunarContract(art, ["ab" * 32])
    assert str(e.value) == want
    for bad in (0, 63, 65):
        with pytest.raises(ValueError, match="PQ-F1"):
            RunarContract(art, ["ab" * bad])
    RunarContract(art, ["ab" * 64])


def test_pq_f1_legacy_stateful_artifact_falls_back_to_anf():
    d = _artifact_dict(_LEGACY, "LW.runar.ts")
    d.pop("pqPubKeyParams")
    art = RunarArtifact.from_dict(d)
    with pytest.raises(ValueError, match="must be exactly 64 bytes, got 32"):
        RunarContract(art, ["ab" * 32, 0])
    RunarContract(art, ["ab" * 64, 0])
