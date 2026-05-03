"""Tests for the .runar.go parser — Python port of the Go reference
``parser_gocontract_test.go``.

Pins a representative slice of the Go DSL surface so the Python parser's
per-format behaviour is verified explicitly rather than only through the
cross-format ``test_parsers.py``.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


P2PKH_SOURCE = """\
package contract

import "github.com/icellan/runar/packages/runar-go"

type P2PKH struct {
    runar.SmartContract
    PubKeyHash runar.ByteString `runar:"readonly"`
}

func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
    runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
    runar.Assert(runar.CheckSig(sig, pubKey))
}
"""


class TestGoP2PKH:
    def test_parses_to_expected_contract_shape(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.go")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "P2PKH"
        assert c.parent_class == "SmartContract"
        assert len(c.properties) >= 1
        # Go `PubKeyHash` -> camelCase `pubKeyHash`.
        assert c.properties[0].name == "pubKeyHash"

    def test_method_visibility_capitalised_means_public(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.go")
        c = result.contract
        assert c is not None
        unlock = next(m for m in c.methods if m.name == "unlock")
        # Exported Go method (capitalised) → public.
        assert unlock.visibility == "public"


class TestGoMethodVisibility:
    def test_capitalised_method_is_public(self):
        source = """\
package contract

import "github.com/icellan/runar/packages/runar-go"

type Checker struct {
    runar.SmartContract
    Target runar.Bigint `runar:"readonly"`
}

func (c *Checker) Verify(a runar.Bigint, b runar.Bigint) {
    runar.Assert(a + b == c.Target)
}
"""
        result = parse_source(source, "Checker.runar.go")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert len(c.methods) >= 1
        m = c.methods[0]
        # Verify -> verify (camelCase).
        assert m.name == "verify"
        assert m.visibility == "public"


class TestGoStateful:
    def test_stateful_counter(self):
        source = """\
package contract

import "github.com/icellan/runar/packages/runar-go"

type Counter struct {
    runar.StatefulSmartContract
    Count runar.Bigint
}

func (c *Counter) Increment() {
    c.Count = c.Count + 1
}
"""
        result = parse_source(source, "Counter.runar.go")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "Counter"
        assert c.parent_class == "StatefulSmartContract"
        # Mutable property (no readonly tag) in stateful contract.
        assert len(c.properties) == 1
        assert c.properties[0].name == "count"
        assert c.properties[0].readonly is False


class TestGoNonRunarStruct:
    def test_non_runar_struct_yields_no_contract(self):
        source = """\
package contract

type Foo struct {
    Bar int
}
"""
        result = parse_source(source, "Foo.runar.go")
        # A struct without a runar embedded base is not a Rúnar contract: it
        # should either produce an error or yield no contract.
        assert result.contract is None or len(result.errors) > 0
