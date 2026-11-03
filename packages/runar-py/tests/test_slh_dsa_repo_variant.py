"""F-133: Python's SLH-DSA verifiers must implement the repo's SHA-256-only
SLH-DSA variant, the one the compiled on-chain verifier and the other six SDKs
implement.

Before F-133 every ``verify_slh_dsa_sha2_*`` builtin routed to the upstream
PyPI ``slh-dsa`` package's real FIPS 205 parameter sets, which use SHA-512 for
the 192/256 sets. A signature the chain accepts was rejected off-chain in
Python, and a FIPS 205 SHA-512 signature (which the chain rejects) was accepted.

What this proves:
  * all six Python verifiers accept signatures produced by the repo TS
    reference signer (192s/192f/256s, vendored in
    ``testdata/slh_dsa_repo_variant_vectors.json``) and the on-chain-accepted
    SLH-DSA-SHA2-256f witness shared with the conformance suite;
  * a genuine FIPS 205 SHA-512 SLH-DSA-SHA2-192f signature is rejected;
  * the 128s set (where FIPS 205 and the repo variant coincide) still accepts
    the official NIST ACVP vector and rejects a 1-bit-flipped signature;
  * verification works without the optional ``slh-dsa`` package.

What this does not prove: it runs no Bitcoin Script. That the vendored
vectors are what the compiled verifier accepts rests on the 256f witness
(executed on @bsv/sdk Spend by conformance/witnesses) and on the generation-
time cross-check described in the vector file's ``_doc``. 128f is covered only
by the shared parameter table, not by a dedicated vector.
"""

import json
from pathlib import Path

import pytest

import runar.slhdsa_impl as slhdsa_impl
from runar.builtins import (
    verify_slh_dsa_sha2_128s,
    verify_slh_dsa_sha2_128f,
    verify_slh_dsa_sha2_192s,
    verify_slh_dsa_sha2_192f,
    verify_slh_dsa_sha2_256s,
    verify_slh_dsa_sha2_256f,
)

VERIFIERS = {
    'sha2_128s': verify_slh_dsa_sha2_128s,
    'sha2_128f': verify_slh_dsa_sha2_128f,
    'sha2_192s': verify_slh_dsa_sha2_192s,
    'sha2_192f': verify_slh_dsa_sha2_192f,
    'sha2_256s': verify_slh_dsa_sha2_256s,
    'sha2_256f': verify_slh_dsa_sha2_256f,
}

_HERE = Path(__file__).resolve()
_VECTORS = json.loads((_HERE.parent / 'testdata' / 'slh_dsa_repo_variant_vectors.json').read_text())


def _repo_root() -> Path:
    for ancestor in _HERE.parents:
        if (ancestor / 'conformance' / 'witnesses').is_dir():
            return ancestor
    raise RuntimeError(f'could not locate the repo root walking up from {_HERE}')


def _witness_256f():
    w = json.loads((_repo_root() / 'conformance' / 'witnesses' / 'real-crypto'
                    / 'post-quantum-slhdsa-256f.json').read_text())
    pk = bytes.fromhex(w['constructorArgs']['pubkey'][2:])
    return [(s['expect'], bytes.fromhex(s['args'][0][2:]), bytes.fromhex(s['args'][1][2:]), pk)
            for s in w['spends']]


def _acvp_128s():
    kat = json.loads((_repo_root() / 'conformance' / 'runtime-vectors'
                      / 'slh-dsa-acvp-kat.json').read_text())
    (v,) = kat['slh_dsa_acvp']
    assert v['param_set'] == 'SLH-DSA-SHA2-128s'
    return bytes.fromhex(v['message']), bytes.fromhex(v['signature']), bytes.fromhex(v['pk'])


@pytest.mark.parametrize('vec', _VECTORS['accept'], ids=lambda v: v['param_set'])
def test_accepts_repo_ts_signer_vectors(vec):
    verify = VERIFIERS[vec['param_set']]
    msg, sig, pk = (bytes.fromhex(vec[k]) for k in ('msg', 'sig', 'pk'))
    assert verify(msg, sig, pk) is True
    tampered = bytearray(sig)
    tampered[-1] ^= 1
    assert verify(msg, bytes(tampered), pk) is False


def test_256f_onchain_witness_agrees():
    spends = _witness_256f()
    assert {e for e, *_ in spends} == {'accept', 'reject'}
    for expect, msg, sig, pk in spends:
        assert verify_slh_dsa_sha2_256f(msg, sig, pk) is (expect == 'accept'), expect


@pytest.mark.parametrize('vec', _VECTORS['reject_fips_sha512'], ids=lambda v: v['param_set'])
def test_rejects_fips_205_sha512_signature(vec):
    msg, sig, pk = (bytes.fromhex(vec[k]) for k in ('msg', 'sig', 'pk'))
    assert VERIFIERS[vec['param_set']](msg, sig, pk) is False


def test_128s_official_acvp_unchanged():
    msg, sig, pk = _acvp_128s()
    assert verify_slh_dsa_sha2_128s(msg, sig, pk) is True
    tampered = bytearray(sig)
    tampered[-1] ^= 1
    assert verify_slh_dsa_sha2_128s(msg, bytes(tampered), pk) is False


def test_public_slh_verify_uses_repo_variant():
    vec = next(v for v in _VECTORS['accept'] if v['param_set'] == 'sha2_192f')
    msg, sig, pk = (bytes.fromhex(vec[k]) for k in ('msg', 'sig', 'pk'))
    assert slhdsa_impl.slh_verify(msg, sig, pk, 'sha2_192f') is True


def test_verify_does_not_need_optional_package(monkeypatch):
    monkeypatch.setattr(slhdsa_impl, '_HAS_SLHDSA', False)
    vec = next(v for v in _VECTORS['accept'] if v['param_set'] == 'sha2_192f')
    msg, sig, pk = (bytes.fromhex(vec[k]) for k in ('msg', 'sig', 'pk'))
    assert verify_slh_dsa_sha2_192f(msg, sig, pk) is True
    assert slhdsa_impl.slh_verify(msg, sig, pk, 'sha2_192f') is True


@pytest.mark.parametrize('param_set', sorted(VERIFIERS))
def test_malformed_inputs_rejected(param_set):
    verify = VERIFIERS[param_set]
    assert verify(b'm', b'', b'') is False
    assert verify(b'm', b'\x00' * 64, b'\x00' * 7) is False


@pytest.mark.skipif(not slhdsa_impl._HAS_SLHDSA, reason="slh-dsa package not installed (pip install slh-dsa)")
def test_keygen_sign_round_trips_through_repo_verifier():
    # slh_keygen/sign use the optional upstream package; for 192f they must
    # produce repo-variant (SHA-256-only) signatures, not FIPS SHA-512 ones.
    kp = slhdsa_impl.slh_keygen('sha2_192f')
    msg = b'runar F-133 keygen round trip'
    sig = kp.sign(msg)
    assert verify_slh_dsa_sha2_192f(msg, sig, kp.pk) is True
