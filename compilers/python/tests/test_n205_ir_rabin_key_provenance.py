"""N-205 (b) — the ``--ir`` loader re-asserts verifyRabinSig key provenance.

``--ir`` skips the frontend, so an ANF program whose verifyRabinSig 4th
argument is a ``load_param`` (the spender picks n = 1 and forges any message),
or whose ``update_prop`` writes a ``load_param`` into the mutable key property,
loaded and compiled. Port of packages/runar-compiler/src/ir/rabin-key-provenance.ts.

What this proves: the Python loader refuses the oracle-price golden with its
key rebound to a parameter (directly and through an ``@ref`` alias) and a
stateful key write from a parameter, with the shared diagnostic, and still
loads the unmodified golden and a literal / property key write.
What it does NOT prove: cross-tier agreement or the helper / ``if``-phi /
``add_output`` shapes (conformance/negatives/ir-rabin-key-provenance.test.ts
covers those against the built CLI).
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from runar_compiler.ir.loader import load_ir

REPO = Path(__file__).resolve().parents[3]
ORACLE = json.loads((REPO / "conformance/tests/oracle-price/expected-ir.json").read_text())
KEY_MSG = (
    "verifyRabinSig public key (4th argument) must be a contract property or a literal; "
    "a spender-supplied Rabin modulus lets anyone forge a signature"
)


def _settle(ir: dict) -> dict:
    return next(m for m in ir["methods"] if m["name"] == "settle")


def _binding(m: dict, name: str) -> dict:
    return next(b for b in m["body"] if b["name"] == name)


def _key_from_param() -> dict:
    ir = copy.deepcopy(ORACLE)
    settle = _settle(ir)
    settle["params"].append({"name": "n", "type": "RabinPubKey"})
    _binding(settle, "t5")["value"] = {"kind": "load_param", "name": "n"}
    return ir


def test_golden_still_loads() -> None:
    load_ir(json.dumps(ORACLE))


def test_literal_key_loads() -> None:
    ir = copy.deepcopy(ORACLE)
    _binding(_settle(ir), "t5")["value"] = {"kind": "load_const", "value": 1000003}
    load_ir(json.dumps(ir))


def test_key_from_load_param_refused() -> None:
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(_key_from_param()))
    assert str(exc.value) == f"IR validation: method 'settle': {KEY_MSG}"


def test_key_alias_of_load_param_refused() -> None:
    ir = _key_from_param()
    settle = _settle(ir)
    at = next(i for i, b in enumerate(settle["body"]) if b["name"] == "t5")
    settle["body"].insert(at + 1, {"name": "k", "value": {"kind": "load_const", "value": "@ref:t5"}})
    _binding(settle, "t6")["value"]["args"][3] = "k"
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(ir))
    assert str(exc.value) == f"IR validation: method 'settle': {KEY_MSG}"


def test_bool_const_key_refused() -> None:
    # bool is an int subclass in Python; it must not pass as an integer literal.
    ir = copy.deepcopy(ORACLE)
    _binding(_settle(ir), "t5")["value"] = {"kind": "load_const", "value": True}
    with pytest.raises(ValueError) as exc:
        load_ir(json.dumps(ir))
    assert str(exc.value) == f"IR validation: method 'settle': {KEY_MSG}"
