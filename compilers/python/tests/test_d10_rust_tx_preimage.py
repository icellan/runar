"""D10 -- a stateless Rust-DSL contract cannot declare tx_preimage.

In the Rust DSL a `tx_preimage` field is the implicit preimage of a stateful
contract, auto-checked at every public method's entry. A contract that
resolves to stateless (#[runar::contract] with no other mutable field, or
#[runar::unsafe_contract]) never checks it, so every extractor read of it is
unverified. This tier used to compile such a contract into a script that can
never be spent; it is now refused by the parser with the shared diagnostic.
Corpus: conformance/negatives/rust-tx-preimage-cases.json.

Proves: each refused shape fails parsing and compiling with the shared
diagnostic; each stateful shape parses as StatefulSmartContract with no
txPreimage property and compiles.
Does not prove: the other six tiers (conformance/negatives covers them).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.compiler import CompilationError, compile_from_source
from runar_compiler.frontend.parser_dispatch import parse_source

_REPO = Path(__file__).resolve().parents[3]
_CORPUS = json.loads((_REPO / "conformance/negatives/rust-tx-preimage-cases.json").read_text())


def test_corpus_size():
    assert len(_CORPUS["refuse"]) >= 5 and len(_CORPUS["accept"]) >= 3


@pytest.mark.parametrize("case", _CORPUS["refuse"], ids=[c["name"] for c in _CORPUS["refuse"]])
def test_refuses_stateless_tx_preimage(case, tmp_path):
    parsed = parse_source(case["src"], case["file"])
    assert any(case["error"] in str(e) for e in parsed.errors), [str(e) for e in parsed.errors]
    path = tmp_path / case["file"]
    path.write_text(case["src"])
    with pytest.raises(CompilationError) as exc:
        compile_from_source(str(path))
    assert case["error"] in str(exc.value)


@pytest.mark.parametrize("case", _CORPUS["accept"], ids=[c["name"] for c in _CORPUS["accept"]])
def test_accepts_stateful_tx_preimage(case, tmp_path):
    parsed = parse_source(case["src"], case["file"])
    assert parsed.errors == []
    assert parsed.contract.parent_class == "StatefulSmartContract"
    assert all(p.name != "txPreimage" for p in parsed.contract.properties)
    path = tmp_path / case["file"]
    path.write_text(case["src"])
    assert compile_from_source(str(path)).script
