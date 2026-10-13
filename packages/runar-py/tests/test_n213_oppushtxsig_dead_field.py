"""N-213 -- the Python half of "remove the dead ``PreparedCall.opPushTxSig``
field (and its wasted ECDSA sign per stateful call) from
Go/Rust/Python/Ruby/Zig SDKs, as F-369 did for TS".

Since BUG-100 the unlocking script carries no spender-supplied OP_PUSH_TX
signature: ``RunarContract._build_stateful_prefix``'s first parameter is
accepted for call-site compatibility but ignored (see its
``del op_sig_hex`` discard). ``op_push_tx_sig`` was documented public surface
on ``PreparedCall`` that backed nothing a caller could use: a caller who read
the field and prepended it to the unlock, as its doc comment implied, would
have produced an INVALID unlock (one extra stack item).

This test proves (a) the field is gone (``PreparedCall`` is a ``dataclass`` --
checked via ``dataclasses.fields`` and plain ``hasattr``) and (b) the
multi-signer ``prepare_call`` -> external ``sign_hash`` -> ``finalize_call``
flow still produces a transaction the mock provider accepts and broadcasts --
removing the field must not disturb the actual unlock.

It does NOT prove anything about the other four SDKs in scope for N-213
(Go/Rust/Ruby/Zig -- each gets its own language-appropriate field-absence
test) or a real on-chain broadcast. Reuses the ``SigCounter`` fixture from
``test_c19_prepared_sighash.py``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest

from runar.ecdsa import ecdsa_sign, ecdsa_verify
from runar.sdk.contract import RunarContract
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.types import DeployOptions, PreparedCall, RunarArtifact, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

SIGNER_KEY = "00" * 31 + "03"
FUNDER_KEY = "00" * 31 + "04"

# Same shape as test_c19_prepared_sighash.py's SigCounter -- a stateful
# contract whose public method takes an external `Sig`, i.e. the
# multi-signer / hardware-wallet shape prepare_call() exists to serve.
SRC = '''from runar import StatefulSmartContract, Bigint, PubKey, Sig, Readonly, public, assert_, check_sig


class SigCounter(StatefulSmartContract):
    count: Bigint
    owner: Readonly[PubKey]

    def __init__(self, count: Bigint, owner: PubKey):
        super().__init__(count, owner)
        self.count = count
        self.owner = owner

    @public
    def inc(self, sig: Sig):
        assert_(check_sig(sig, self.owner))
        self.count = self.count + 1
'''


def _artifact() -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(SRC, "SigCounter.runar.py")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


def _funded_signer(provider: MockProvider, key_hex: str, satoshis: int) -> LocalSigner:
    signer = LocalSigner(key_hex)
    provider.add_utxo(signer.get_address(), Utxo(
        txid=key_hex[:64],
        output_index=0,
        satoshis=satoshis,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    return signer


def _deploy():
    """Deploy SigCounter (count = 5, owner = the signer's pubkey)."""
    artifact = _artifact()
    provider = MockProvider("testnet")
    signer = _funded_signer(provider, SIGNER_KEY, 500_000)
    _funded_signer(provider, FUNDER_KEY, 500_000)

    contract = RunarContract(artifact, [5, signer.get_public_key()])
    contract.deploy(provider, signer, DeployOptions(satoshis=50_000))
    return contract, provider, signer


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def test_prepared_call_has_no_op_push_tx_sig_field():
    """PreparedCall carries no op_push_tx_sig field at all -- not even an
    always-empty one."""
    field_names = {f.name for f in dataclasses.fields(PreparedCall)}
    assert "op_push_tx_sig" not in field_names, (
        f"PreparedCall still declares the dead op_push_tx_sig field: {field_names}"
    )

    contract, provider, signer = _deploy()
    prepared = contract.prepare_call("inc", [None], provider, signer)
    assert not hasattr(prepared, "op_push_tx_sig"), (
        "a live PreparedCall instance still carries op_push_tx_sig as an attribute"
    )


def test_external_sign_hash_wallet_flow_still_works_without_the_field():
    """End-to-end: the multi-signer flow (prepare_call -> external
    sign_hash(sighash) -> finalize_call -> broadcast) must still work after
    removing op_push_tx_sig -- nothing in that path ever needed it."""
    contract, provider, signer = _deploy()

    prepared = contract.prepare_call("inc", [None], provider, signer)
    assert len(prepared.sig_indices) == 1, (
        f"expected exactly one external Sig slot, got {prepared.sig_indices}"
    )

    digest = bytes.fromhex(prepared.sighash)
    assert len(digest) == 32, f"prepared.sighash must be a 32-byte digest, got {len(digest)} bytes"
    der = ecdsa_sign(int(SIGNER_KEY, 16), digest)
    sig_hex = der.hex() + "41"  # ALL | FORKID

    on_chain_digest = _sha256d(bytes.fromhex(prepared.preimage))
    pub_key = bytes.fromhex(signer.get_public_key())
    assert ecdsa_verify(der, pub_key, on_chain_digest), (
        "the external wallet's signature over PreparedCall.sighash does NOT verify "
        "against the on-chain BIP-143 digest -- removing op_push_tx_sig broke the unlock"
    )

    contract.finalize_call(prepared, {prepared.sig_indices[0]: sig_hex}, provider)

    txs = provider.get_broadcasted_txs()
    assert len(txs) == 2, f"expected deploy + call broadcasts, got {len(txs)}"
    assert sig_hex in txs[1], (
        "the externally-produced signature must appear in the broadcast transaction"
    )
