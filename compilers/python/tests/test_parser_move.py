"""Tests for the .runar.move parser — Python port of the Go reference
``parser_move_test.go``.

Each test pins a representative slice of the Move-style surface so the
Python parser's per-format behaviour is verified explicitly.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


P2PKH_SOURCE = """\
module P2PKH {
    use runar::SmartContract;
    use runar::hash160;
    use runar::checkSig;

    struct P2PKH has SmartContract {
        pub_key_hash: Addr,
    }

    public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash);
        assert!(checkSig(sig, pub_key));
    }
}
"""


class TestMoveP2PKH:
    def test_parses_to_expected_contract_shape(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.move")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "P2PKH"
        assert c.parent_class == "SmartContract"


class TestMoveProperties:
    def test_properties_and_methods(self):
        source = """\
module Adder {
    use runar::SmartContract;

    struct Adder has SmartContract {
        target: bigint,
    }

    public fun verify(contract: &Adder, a: bigint, b: bigint) {
        assert!(a + b == contract.target);
    }
}
"""
        result = parse_source(source, "Adder.runar.move")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert len(c.properties) >= 1
        assert c.properties[0].name == "target"
        assert len(c.methods) >= 1
        assert c.methods[0].name == "verify"


class TestMoveStateful:
    def test_stateful_counter(self):
        source = """\
module Counter {
    use runar::StatefulSmartContract;

    resource struct Counter {
        count: &mut Int,
    }

    public fun increment(contract: &mut Counter) {
        contract.count = contract.count + 1;
    }
}
"""
        result = parse_source(source, "Counter.runar.move")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.parent_class == "StatefulSmartContract"


class TestMoveRejection:
    def test_invalid_syntax_produces_error(self):
        source = """\
module {
    // missing name
}
"""
        result = parse_source(source, "bad.runar.move")
        assert result.contract is None or len(result.errors) > 0


class TestMoveMultipleMethods:
    def test_two_public_functions(self):
        source = """\
module Multi {
    use runar::SmartContract;

    struct Multi has SmartContract {
        x: bigint,
    }

    public fun method1(contract: &Multi, a: bigint) {
        assert!(a == contract.x);
    }

    public fun method2(contract: &Multi, b: bigint) {
        assert!(b == contract.x);
    }
}
"""
        result = parse_source(source, "Multi.runar.move")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert len(c.methods) == 2


# ---------------------------------------------------------------------------
# R-183 (CL-BUG-063): the seven tiers' Move type tables had drifted.
#
# Measured before the fix, across all seven Move frontends:
#
#   Bigint  -> bigint      accepted by 3 of 7 (python, ruby, java)
#   Bytes   -> ByteString  accepted by 2 of 7 (go, rust)
#   address -> Addr        accepted by 4 of 7 (ts, go, rust, ruby)
#
# The same .runar.move source therefore parsed in some tiers and silently
# degraded to a custom type in others. This tier was missing `Bytes` and
# `address`.
# ---------------------------------------------------------------------------
import pytest

from runar_compiler.frontend.parser_move import _move_map_type


@pytest.mark.parametrize(
    "alias,want",
    [
        ("Int", "bigint"), ("Bigint", "bigint"), ("u64", "bigint"),
        ("Bool", "boolean"), ("bool", "boolean"),
        ("vector", "ByteString"), ("Bytes", "ByteString"),
        ("address", "Addr"),
    ],
)
def test_r183_move_type_alias_parity(alias, want):
    mapped = _move_map_type(alias)
    assert getattr(mapped, "name", None) == want, (
        f"{alias} mapped to {mapped!r}; every tier must map it to {want}"
    )
