"""PQ-F1: the artifact lists every constructor param passed directly as the
public key of verifyWOTS / verifySLHDSA_SHA2_*, with the exact byte length that
verifier needs, so every SDK can refuse a wrong-length key before deploying
(stateless artifacts carry no ANF to walk).

Proves: the exact JSON text of ``pqPubKeyParams`` (key order included) for a
stateless WOTS contract, an SLH-DSA-192f contract, and a key behind a local
alias plus a key read in a private helper; absent for a key passed as a method
argument.
Does not prove: cross-tier equality (conformance/negatives/artifact-flag-parity.test.ts).
"""
import json

import pytest

from runar_compiler.compiler import artifact_to_json, compile_from_source_str_with_result


def _pq(src):
    r = compile_from_source_str_with_result(src, "C.runar.ts")
    assert r.artifact is not None, [d.message for d in r.diagnostics]
    d = json.loads(artifact_to_json(r.artifact))
    if "pqPubKeyParams" not in d:
        return None
    return json.dumps(d["pqPubKeyParams"], separators=(",", ":"))


CASES = [
    (
        """import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly pk: ByteString;
  constructor(pk: ByteString) { super(pk); this.pk = pk; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pk)); }
}""",
        '[{"index":0,"name":"pk","scheme":"verifyWOTS","length":64}]',
    ),
    (
        """import { SmartContract, ByteString, assert, verifySLHDSA_SHA2_192f } from 'runar-lang';
class C extends SmartContract {
  readonly pk: ByteString;
  constructor(pk: ByteString) { super(pk); this.pk = pk; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifySLHDSA_SHA2_192f(msg, sig, this.pk)); }
}""",
        '[{"index":0,"name":"pk","scheme":"verifySLHDSA_SHA2_192f","length":48}]',
    ),
    (
        """import { SmartContract, ByteString, assert, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly tag: bigint;
  readonly a: ByteString;
  readonly b: ByteString;
  constructor(tag: bigint, a: ByteString, b: ByteString) { super(tag, a, b); this.tag = tag; this.a = a; this.b = b; }
  private checkB(msg: ByteString, sig: ByteString): boolean { return verifyWOTS(msg, sig, this.b); }
  public spend(msg: ByteString, sig: ByteString, sig2: ByteString) {
    assert(this.checkB(msg, sig2));
    const k = this.a;
    assert(verifyWOTS(msg, sig, k));
    assert(this.tag > 0n);
  }
}""",
        '[{"index":1,"name":"a","scheme":"verifyWOTS","length":64},'
        '{"index":2,"name":"b","scheme":"verifyWOTS","length":64}]',
    ),
    (
        """import { SmartContract, ByteString, Sha256, assert, sha256, verifyWOTS } from 'runar-lang';
class C extends SmartContract {
  readonly h: Sha256;
  constructor(h: Sha256) { super(h); this.h = h; }
  public spend(msg: ByteString, sig: ByteString, pk: ByteString) { assert(sha256(pk) === this.h); assert(verifyWOTS(msg, sig, pk)); }
}""",
        None,
    ),
]


@pytest.mark.parametrize("src,want", CASES)
def test_pq_pubkey_params(src, want):
    assert _pq(src) == want
