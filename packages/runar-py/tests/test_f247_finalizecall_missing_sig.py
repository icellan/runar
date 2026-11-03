"""F-247 (CL-BUG-136, MEDIUM/P2): ``finalize_call`` broadcasts a 72-byte
all-zero placeholder when a declared ``sig_indices`` slot is left unfilled.

``prepare_call`` stubs every auto-signed ``Sig`` param with a 72-zero-byte
placeholder and records its arg index in ``sig_indices``. ``finalize_call``
only overwrote ``resolved_args[idx]`` for the indices actually present in
the caller-supplied ``signatures`` map -- nothing checked that every entry
in ``prepared.sig_indices`` was covered before the primary unlocking script
was assembled and handed to ``provider.broadcast()``. Ported from the TS fix
in ``packages/runar-sdk/src/contract.ts``.

This test deliberately avoids MockProvider's always-ack classmethod
constructor (which would need an ``always_ack_allowlist.json`` entry, and the default validating
``MockProvider`` would mask the bug by rejecting the placeholder-signed
broadcast for the WRONG reason -- script invalidity caught AT broadcast time
-- rather than showing whether ``finalize_call`` refuses BEFORE calling
``provider.broadcast()`` at all). Instead it hand-rolls a minimal
``Provider`` subclass whose ``broadcast()`` acks anything, like a real
network node that does not pre-validate scripts.
"""

from __future__ import annotations

import json

import pytest

from runar.sdk.contract import RunarContract
from runar.sdk.local_signer import LocalSigner
from runar.sdk.provider import MockProvider, Provider
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.types import DeployOptions, RunarArtifact, Utxo

compiler = pytest.importorskip("runar_compiler.compiler")

SIGNER_KEY = "00" * 31 + "0a"

SRC = '''from runar import SmartContract, PubKey, Sig, public, assert_, check_sig


class F247SigCheck(SmartContract):
    owner: PubKey

    def __init__(self, owner: PubKey):
        super().__init__(owner)
        self.owner = owner

    @public
    def unlock(self, sig: Sig):
        assert_(check_sig(sig, self.owner))
'''


def _artifact() -> RunarArtifact:
    result = compiler.compile_from_source_str_with_result(SRC, "F247SigCheck.runar.py")
    errs = [d.message for d in result.diagnostics if d.severity == "error"]
    assert result.artifact is not None, errs
    return RunarArtifact.from_dict(json.loads(compiler.artifact_to_json(result.artifact)))


class AckAnythingProvider(Provider):
    """Delegates every read to an underlying MockProvider but broadcast()
    acks unconditionally -- no script validation -- mirroring a real
    network provider. Not a MockProvider always-ack usage: a plain
    hand-rolled Provider subclass."""

    def __init__(self, inner: MockProvider):
        self._inner = inner
        self.broadcasted_txs: list[str] = []

    def get_transaction(self, txid: str):
        return self._inner.get_transaction(txid)

    def broadcast(self, tx) -> str:
        raw_tx = tx if isinstance(tx, str) else tx.hex()
        self.broadcasted_txs.append(raw_tx)
        return f"{len(self.broadcasted_txs):064x}"

    def get_utxos(self, address: str):
        return self._inner.get_utxos(address)

    def get_contract_utxo(self, script_hash: str):
        return self._inner.get_contract_utxo(script_hash)

    def get_network(self) -> str:
        return self._inner.get_network()

    def get_fee_rate(self) -> int:
        return self._inner.get_fee_rate()

    def get_raw_transaction(self, txid: str) -> str:
        return self._inner.get_raw_transaction(txid)


def _deploy():
    artifact = _artifact()
    mock = MockProvider("testnet")
    signer = LocalSigner(SIGNER_KEY)
    mock.add_utxo(signer.get_address(), Utxo(
        txid=SIGNER_KEY[:64],
        output_index=0,
        satoshis=500_000,
        script=build_p2pkh_script(signer.get_public_key()),
    ))
    provider = AckAnythingProvider(mock)

    contract = RunarContract(artifact, [signer.get_public_key()])
    contract.deploy(provider, signer, DeployOptions(satoshis=50_000))
    return contract, provider, signer


def test_finalize_call_with_missing_sig_index_refuses_instead_of_broadcasting():
    """What this test proves: calling finalize_call with an empty signatures
    dict for a method with one declared sig_indices entry raises before
    provider.broadcast() is ever reached (the broadcast count does not grow).

    What this test does NOT prove: multi-signer (2+ sig_indices) coverage
    with SOME but not all slots filled -- covered logically by the same
    missing-index scan in the fix, but not exercised by a dedicated fixture
    here.
    """
    contract, provider, signer = _deploy()

    prepared = contract.prepare_call("unlock", [None], provider, signer)
    assert len(prepared.sig_indices) == 1, (
        f"expected exactly one external Sig slot, got {prepared.sig_indices}"
    )

    broadcast_count_before = len(provider.broadcasted_txs)

    # Caller forgets the one declared signature slot entirely.
    with pytest.raises(Exception, match=r"(?i)sig|signature"):
        contract.finalize_call(prepared, {}, provider)

    assert len(provider.broadcasted_txs) == broadcast_count_before, (
        "provider.broadcast was called despite the missing signature"
    )
