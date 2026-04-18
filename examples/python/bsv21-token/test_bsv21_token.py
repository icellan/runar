"""Tests for the Python BSV21Token contract (P2PKH lock + BSV-21 inscription)."""

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
    bsv21_deploy_mint,
    bsv21_transfer,
    parse_inscription_envelope,
)


SOURCE_PATH = Path(__file__).parent / "BSV21Token.runar.py"

contract_mod = load_contract(str(SOURCE_PATH))
BSV21Token = contract_mod.BSV21Token


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
    c = BSV21Token(pub_key_hash=hash160(ALICE.pub_key))
    c.unlock(ALICE.test_sig, ALICE.pub_key)


def test_unlock_wrong_key_fails():
    c = BSV21Token(pub_key_hash=hash160(ALICE.pub_key))
    with pytest.raises(AssertionError):
        c.unlock(BOB.test_sig, BOB.pub_key)


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def test_compile():
    from runar import compile_check
    source = SOURCE_PATH.read_text()
    compile_check(source, "BSV21Token.runar.py")


def test_compiles_to_valid_artifact():
    artifact = _compile_artifact()
    assert artifact.contract_name == "BSV21Token"


# ---------------------------------------------------------------------------
# BSV-21 deploy+mint inscription
# ---------------------------------------------------------------------------

def test_deploy_mint_inscription_with_all_fields():
    artifact = _compile_artifact()
    inscription = bsv21_deploy_mint(
        "1000000",
        dec="18",
        sym="RNR",
        icon="b61b0172d95e266c18aea0c624db987e971a5d6d4ebc2aaed85da4642d635735_0",
    )
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])
    contract.with_inscription(inscription)

    parsed = parse_inscription_envelope(contract.get_locking_script())
    assert parsed is not None
    assert parsed.content_type == "application/bsv-20"

    data = json.loads(_hex_to_utf8(parsed.data))
    assert data["p"] == "bsv-20"
    assert data["op"] == "deploy+mint"
    assert data["amt"] == "1000000"
    assert data["dec"] == "18"
    assert data["sym"] == "RNR"
    assert data["icon"] == "b61b0172d95e266c18aea0c624db987e971a5d6d4ebc2aaed85da4642d635735_0"


def test_deploy_mint_inscription_with_minimal_fields():
    artifact = _compile_artifact()
    inscription = bsv21_deploy_mint("500")
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])
    contract.with_inscription(inscription)

    parsed = parse_inscription_envelope(contract.get_locking_script())
    data = json.loads(_hex_to_utf8(parsed.data))
    assert data["p"] == "bsv-20"
    assert data["op"] == "deploy+mint"
    assert data["amt"] == "500"
    assert "dec" not in data
    assert "sym" not in data


# ---------------------------------------------------------------------------
# BSV-21 transfer inscription
# ---------------------------------------------------------------------------

def test_transfer_inscription_with_token_id():
    artifact = _compile_artifact()
    token_id = "3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1"
    inscription = bsv21_transfer(token_id, "100")
    contract = RunarContract(artifact, [ALICE.pub_key_hash.hex()])
    contract.with_inscription(inscription)

    parsed = parse_inscription_envelope(contract.get_locking_script())
    assert parsed is not None
    assert parsed.content_type == "application/bsv-20"

    data = json.loads(_hex_to_utf8(parsed.data))
    assert data["p"] == "bsv-20"
    assert data["op"] == "transfer"
    assert data["id"] == token_id
    assert data["amt"] == "100"


# ---------------------------------------------------------------------------
# Round-trip through from_utxo
# ---------------------------------------------------------------------------

def test_deploy_mint_inscription_survives_from_utxo_round_trip():
    artifact = _compile_artifact()
    inscription = bsv21_deploy_mint("1000000", sym="RNR")
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
    assert data["op"] == "deploy+mint"
    assert data["amt"] == "1000000"
    assert data["sym"] == "RNR"


def test_transfer_inscription_survives_from_utxo_round_trip():
    artifact = _compile_artifact()
    token_id = "abc123_0"
    inscription = bsv21_transfer(token_id, "50")
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

    data = json.loads(_hex_to_utf8(reconnected.inscription.data))
    assert data["op"] == "transfer"
    assert data["id"] == token_id
    assert data["amt"] == "50"
