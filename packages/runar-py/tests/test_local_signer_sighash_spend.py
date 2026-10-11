"""N-108: LocalSigner honours the caller's sighash type on BOTH backends.

The default backend (bsv-sdk, picked whenever it is installed) used to build a
``P2PKH().unlock(priv)`` template and call ``tx.sign()``, which always signs
ALL|FORKID and appends 0x41. A method declared with SINGLE, NONE or
ANYONECANPAY then got a signature over the wrong digest. The pure-Python
fallback already honoured the flag.

Oracle: bsv-sdk's ``Spend`` interpreter (the acceptance oracle the Python
MockProvider uses), not the repo's own BIP-143 builder. Each signature is put
in a real P2PKH unlocking script on a 2-in/2-out transaction (two outputs so
SINGLE at input 1 differs from NONE) and the interpreter runs OP_CHECKSIG
under the flag byte the signer appended.

Proves: for every FORKID mode, each backend's signature carries the requested
flag byte and the interpreter accepts it under that flag; the same signature
with its flag byte swapped to ALL|FORKID is rejected (so the check is not
vacuous: the digest really depends on the flag).
Does not prove: broadcast acceptance by a node, or multi-input contract calls
(those go through contract.py, which this test does not touch).
"""

from __future__ import annotations

import hashlib
import importlib.util
import os

import pytest

# Same CI gate as test_script_vm.py: a missing bsv-sdk in CI must be loud.
if os.environ.get("CI") and importlib.util.find_spec("bsv") is None:
    pytest.fail(
        "test_local_signer_sighash_spend.py: CI environment detected ($CI is set) "
        "but the optional `bsv-sdk` package is not installed — these tests would "
        "silently skip. Install it in CI (`pip install bsv-sdk`).",
        pytrace=False,
    )

pytest.importorskip("bsv", reason="bsv-sdk not installed (runar[script-vm] extra)")

from bsv.script.script import Script  # noqa: E402
from bsv.script.spend import Spend  # noqa: E402
from bsv.transaction import Transaction  # noqa: E402
from bsv.transaction_input import TransactionInput  # noqa: E402
from bsv.transaction_output import TransactionOutput  # noqa: E402

import runar.sdk.local_signer as ls_module  # noqa: E402
from runar._ripemd160 import ripemd160_digest  # noqa: E402

PRIV_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SOURCE_SATS = 10_000
MODES = [0x41, 0x42, 0x43, 0xC1, 0xC2, 0xC3]


def _p2pkh(pub_hex: str) -> str:
    pkh = ripemd160_digest(hashlib.sha256(bytes.fromhex(pub_hex)).digest())
    return "76a914" + pkh.hex() + "88ac"


def _push(data: bytes) -> bytes:
    assert len(data) < 0x4C
    return bytes([len(data)]) + data


def _unsigned_tx(locking_hex: str) -> Transaction:
    tx = Transaction()
    for idx, txid in enumerate(("11" * 32, "22" * 32)):
        tx.add_input(TransactionInput(
            source_txid=txid, source_output_index=idx,
            unlocking_script=Script(), sequence=0xFFFFFFFE - idx,
        ))
    tx.add_output(TransactionOutput(locking_script=Script(bytes.fromhex(locking_hex)), satoshis=4_000))
    tx.add_output(TransactionOutput(locking_script=Script(bytes.fromhex(locking_hex)), satoshis=5_000))
    return tx


def _spend_ok(tx: Transaction, input_index: int, locking_hex: str, sig_hex: str, pub_hex: str) -> bool:
    unlocking = Script(_push(bytes.fromhex(sig_hex)) + _push(bytes.fromhex(pub_hex)))
    inp = tx.inputs[input_index]
    spend = Spend({
        "sourceTXID": inp.source_txid,
        "sourceOutputIndex": inp.source_output_index,
        "sourceSatoshis": SOURCE_SATS,
        "lockingScript": Script(bytes.fromhex(locking_hex)),
        "transactionVersion": tx.version,
        "otherInputs": [v for j, v in enumerate(tx.inputs) if j != input_index],
        "outputs": tx.outputs,
        "inputIndex": input_index,
        "unlockingScript": unlocking,
        "inputSequence": inp.sequence,
        "lockTime": tx.locktime,
    })
    try:
        return bool(spend.validate())
    except Exception:
        return False


def _signer(backend: str, monkeypatch) -> ls_module.LocalSigner:
    if backend == "fallback":
        monkeypatch.setattr(ls_module, "_BSV_SDK_AVAILABLE", False)
    signer = ls_module.LocalSigner(PRIV_HEX)
    assert signer._backend == backend
    return signer


@pytest.mark.parametrize("backend", ["bsv", "fallback"])
@pytest.mark.parametrize("flag", MODES, ids=[f"0x{m:02x}" for m in MODES])
def test_local_signer_signs_requested_sighash(backend: str, flag: int, monkeypatch) -> None:
    signer = _signer(backend, monkeypatch)
    pub_hex = signer.get_public_key()
    locking_hex = _p2pkh(pub_hex)
    tx = _unsigned_tx(locking_hex)
    input_index = 1

    sig_hex = signer.sign(tx.hex(), input_index, locking_hex, SOURCE_SATS, flag)

    assert sig_hex[-2:] == f"{flag:02x}", (
        f"{backend}: appended flag byte {sig_hex[-2:]} != requested {flag:02x}"
    )
    assert _spend_ok(tx, input_index, locking_hex, sig_hex, pub_hex), (
        f"{backend}: bsv-sdk Spend rejects the LocalSigner signature under 0x{flag:02x}"
    )
    if flag != 0x41:
        relabelled = sig_hex[:-2] + "41"
        assert not _spend_ok(tx, input_index, locking_hex, relabelled, pub_hex), (
            f"{backend}: 0x{flag:02x} signature also verifies as ALL|FORKID — "
            "the oracle is not distinguishing sighash modes"
        )
