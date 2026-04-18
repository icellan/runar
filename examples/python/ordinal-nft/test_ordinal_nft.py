"""Tests for the Python OrdinalNFT contract (P2PKH lock + 1sat inscription)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import load_contract  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "compilers" / "python"))

from runar_compiler.compiler import compile_from_source, artifact_to_json  # noqa: E402
from runar import hash160, ALICE, BOB  # noqa: E402
from runar.sdk import (  # noqa: E402
    Inscription,
    RunarArtifact,
    RunarContract,
    Utxo,
    build_inscription_envelope,
    parse_inscription_envelope,
)


SOURCE_PATH = Path(__file__).parent / "OrdinalNFT.runar.py"

contract_mod = load_contract(str(SOURCE_PATH))
OrdinalNFT = contract_mod.OrdinalNFT


def _utf8_to_hex(s: str) -> str:
    return s.encode("utf-8").hex()


def _hex_to_utf8(h: str) -> str:
    return bytes.fromhex(h).decode("utf-8")


def _compile_artifact() -> RunarArtifact:
    compiler_artifact = compile_from_source(str(SOURCE_PATH))
    artifact_dict = json.loads(artifact_to_json(compiler_artifact))
    return RunarArtifact.from_dict(artifact_dict)


# ---------------------------------------------------------------------------
# Business logic
# ---------------------------------------------------------------------------

def test_unlock_valid():
    c = OrdinalNFT(pub_key_hash=hash160(ALICE.pub_key))
    c.unlock(ALICE.test_sig, ALICE.pub_key)


def test_unlock_wrong_key_fails():
    c = OrdinalNFT(pub_key_hash=hash160(ALICE.pub_key))
    with pytest.raises(AssertionError):
        c.unlock(BOB.test_sig, BOB.pub_key)


def test_stateless_state_exposes_constructor_arg():
    c = OrdinalNFT(pub_key_hash=hash160(ALICE.pub_key))
    # The stateless contract's constructor arg is retained on the Python instance.
    assert c.pub_key_hash == hash160(ALICE.pub_key)


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def test_compile():
    from runar import compile_check
    source = SOURCE_PATH.read_text()
    compile_check(source, "OrdinalNFT.runar.py")


def test_compiles_to_valid_artifact():
    artifact = _compile_artifact()
    assert artifact.contract_name == "OrdinalNFT"
    assert len(artifact.abi.methods) == 1
    assert artifact.abi.methods[0].name == "unlock"


# ---------------------------------------------------------------------------
# SDK inscription flow
# ---------------------------------------------------------------------------

def test_attaches_image_inscription_to_locking_script():
    artifact = _compile_artifact()
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])

    png_data = "89504e470d0a1a0a"
    contract.with_inscription(Inscription(content_type="image/png", data=png_data))

    locking_script = contract.get_locking_script()

    expected_envelope = build_inscription_envelope("image/png", png_data)
    assert expected_envelope in locking_script

    parsed = parse_inscription_envelope(locking_script)
    assert parsed is not None
    assert parsed.content_type == "image/png"
    assert parsed.data == png_data


def test_attaches_text_inscription_to_locking_script():
    artifact = _compile_artifact()
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])

    text_data = _utf8_to_hex("Hello, Ordinals!")
    contract.with_inscription(Inscription(content_type="text/plain", data=text_data))

    parsed = parse_inscription_envelope(contract.get_locking_script())
    assert parsed is not None
    assert parsed.content_type == "text/plain"
    assert _hex_to_utf8(parsed.data) == "Hello, Ordinals!"


def test_round_trips_inscription_through_from_utxo():
    artifact = _compile_artifact()
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])

    png_data = "89504e470d0a1a0a"
    contract.with_inscription(Inscription(content_type="image/png", data=png_data))

    locking_script = contract.get_locking_script()

    reconnected = RunarContract.from_utxo(
        artifact,
        Utxo(
            txid="00" * 32,
            output_index=0,
            satoshis=1,
            script=locking_script,
        ),
    )

    assert reconnected.inscription is not None
    assert reconnected.inscription.content_type == "image/png"
    assert reconnected.inscription.data == png_data


def test_locking_script_without_inscription_has_no_envelope():
    artifact = _compile_artifact()
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])

    locking_script = contract.get_locking_script()
    assert parse_inscription_envelope(locking_script) is None


def test_with_inscription_returns_self_for_chaining():
    artifact = _compile_artifact()
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])
    result = contract.with_inscription(Inscription(content_type="text/plain", data=""))
    assert result is contract
