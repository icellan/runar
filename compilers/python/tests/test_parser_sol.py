"""Tests for the .runar.sol parser — Python port of the Go reference
``parser_sol_test.go``.

Each test pins a representative slice of the Solidity-like surface so the
Python parser's per-format behaviour is verified explicitly rather than only
through the cross-format ``test_parsers.py``.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


# ---------------------------------------------------------------------------
# P2PKH — basic stateless contract.
# ---------------------------------------------------------------------------

P2PKH_SOURCE = """\
// SPDX-License-Identifier: MIT
pragma runar ^1.0.0;

import "runar-lang";

contract P2PKH is SmartContract {
    Addr immutable pubKeyHash;

    constructor(Addr _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
"""


class TestSolP2PKH:
    def test_parses_to_expected_contract_shape(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.sol")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "P2PKH"
        assert c.parent_class == "SmartContract"
        assert len(c.properties) == 1
        assert c.properties[0].name == "pubKeyHash"

    def test_unlock_method_signature(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.sol")
        c = result.contract
        assert c is not None
        unlock = next(m for m in c.methods if m.name == "unlock")
        assert unlock.visibility == "public"
        # `sig` and `pubKey` — `this`/contract-receiver isn't a Solidity param.
        assert [p.name for p in unlock.params] == ["sig", "pubKey"]


# ---------------------------------------------------------------------------
# Adder — methods + params.
# ---------------------------------------------------------------------------


class TestSolMethodsAndParams:
    def test_methods_and_params(self):
        source = """\
pragma runar ^1.0.0;
import "runar-lang";

contract Adder is SmartContract {
    int immutable target;

    constructor(int _target) {
        target = _target;
    }

    function verify(int a, int b) public {
        require(a + b == target);
    }
}
"""
        result = parse_source(source, "Adder.runar.sol")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert len(c.methods) == 1
        m = c.methods[0]
        assert m.name == "verify"
        assert m.visibility == "public"
        assert len(m.params) == 2


# ---------------------------------------------------------------------------
# Stateful counter.
# ---------------------------------------------------------------------------


class TestSolStateful:
    def test_stateful_counter(self):
        source = """\
pragma runar ^1.0.0;
import "runar-lang";

contract Counter is StatefulSmartContract {
    int count;

    constructor(int _count) {
        count = _count;
    }

    function increment() public {
        count = count + 1;
    }
}
"""
        result = parse_source(source, "Counter.runar.sol")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "Counter"
        assert c.parent_class == "StatefulSmartContract"


# ---------------------------------------------------------------------------
# Multiple properties.
# ---------------------------------------------------------------------------


class TestSolMultipleProperties:
    def test_two_props_in_declaration_order(self):
        source = """\
pragma runar ^1.0.0;
import "runar-lang";

contract TwoProps is SmartContract {
    Addr immutable addr;
    PubKey immutable key;

    constructor(Addr _addr, PubKey _key) {
        addr = _addr;
        key = _key;
    }

    function check(int x) public {
        require(x == 1);
    }
}
"""
        result = parse_source(source, "TwoProps.runar.sol")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert [p.name for p in c.properties] == ["addr", "key"]


# ---------------------------------------------------------------------------
# Rejection.
# ---------------------------------------------------------------------------


class TestSolRejection:
    def test_invalid_syntax_produces_error(self):
        source = "contract { /* missing name */ }"
        result = parse_source(source, "bad.runar.sol")
        # Either the contract is None or errors are reported — never both clean.
        assert result.contract is None or len(result.errors) > 0
