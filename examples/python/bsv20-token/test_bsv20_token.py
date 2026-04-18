"""Tests for the Python BSV20Token contract (P2PKH lock + BSV-20 inscription)."""

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
    RunarArtifact,
    RunarContract,
    Utxo,
    bsv20_deploy,
    bsv20_mint,
    bsv20_transfer,
    parse_inscription_envelope,
)


SOURCE_PATH = Path(__file__).parent / "BSV20Token.runar.py"

contract_mod = load_contract(str(SOURCE_PATH))
BSV20Token = contract_mod.BSV20Token


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
    c = BSV20Token(pub_key_hash=hash160(ALICE.pub_key))
    c.unlock(ALICE.test_sig, ALICE.pub_key)


def test_unlock_wrong_key_fails():
    c = BSV20Token(pub_key_hash=hash160(ALICE.pub_key))
    with pytest.raises(AssertionError):
        c.unlock(BOB.test_sig, BOB.pub_key)


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def test_compile():
    from runar import compile_check
    source = SOURCE_PATH.read_text()
    compile_check(source, "BSV20Token.runar.py")


def test_compiles_to_valid_artifact():
    artifact = _compile_artifact()
    assert artifact.contract_name == "BSV20Token"


# ---------------------------------------------------------------------------
# BSV-20 deploy inscription
# ---------------------------------------------------------------------------

def test_deploy_inscription_has_correct_json():
    artifact = _compile_artifact()
    inscription = bsv20_deploy("RUNAR", "21000000", lim="1000")
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])
    contract.with_inscription(inscription)

    locking_script = contract.get_locking_script()
    parsed = parse_inscription_envelope(locking_script)

    assert parsed is not None
    assert parsed.content_type == "application/bsv-20"

    data = json.loads(_hex_to_utf8(parsed.data))
    assert data["p"] == "bsv-20"
    assert data["op"] == "deploy"
    assert data["tick"] == "RUNAR"
    assert data["max"] == "21000000"
    assert data["lim"] == "1000"


def test_deploy_inscription_with_decimals():
    artifact = _compile_artifact()
    inscription = bsv20_deploy("USDT", "100000000", dec="8")
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])
    contract.with_inscription(inscription)

    parsed = parse_inscription_envelope(contract.get_locking_script())
    data = json.loads(_hex_to_utf8(parsed.data))
    assert data["dec"] == "8"


# ---------------------------------------------------------------------------
# BSV-20 mint inscription
# ---------------------------------------------------------------------------

def test_mint_inscription_has_correct_json():
    artifact = _compile_artifact()
    inscription = bsv20_mint("RUNAR", "1000")
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])
    contract.with_inscription(inscription)

    parsed = parse_inscription_envelope(contract.get_locking_script())
    assert parsed is not None
    assert parsed.content_type == "application/bsv-20"

    data = json.loads(_hex_to_utf8(parsed.data))
    assert data["p"] == "bsv-20"
    assert data["op"] == "mint"
    assert data["tick"] == "RUNAR"
    assert data["amt"] == "1000"


# ---------------------------------------------------------------------------
# BSV-20 transfer inscription
# ---------------------------------------------------------------------------

def test_transfer_inscription_has_correct_json():
    artifact = _compile_artifact()
    inscription = bsv20_transfer("RUNAR", "50")
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])
    contract.with_inscription(inscription)

    parsed = parse_inscription_envelope(contract.get_locking_script())
    assert parsed is not None
    assert parsed.content_type == "application/bsv-20"

    data = json.loads(_hex_to_utf8(parsed.data))
    assert data["p"] == "bsv-20"
    assert data["op"] == "transfer"
    assert data["tick"] == "RUNAR"
    assert data["amt"] == "50"


# ---------------------------------------------------------------------------
# Round-trip through from_utxo
# ---------------------------------------------------------------------------

def test_inscription_survives_from_utxo_round_trip():
    artifact = _compile_artifact()
    inscription = bsv20_deploy("TEST", "1000")
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])
    contract.with_inscription(inscription)

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
    assert reconnected.inscription.content_type == "application/bsv-20"

    data = json.loads(_hex_to_utf8(reconnected.inscription.data))
    assert data["p"] == "bsv-20"
    assert data["op"] == "deploy"
    assert data["tick"] == "TEST"
    assert data["max"] == "1000"
