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


# ---------------------------------------------------------------------------
# F-010: a method is a contract method only if its receiver IS the contract.
# This tier silently dropped a method on another type (and any method declared
# before the contract struct); the TS reference, Go and Ruby made it a PUBLIC
# entry point. The rule (user decision R9), diagnostics verbatim in all tiers:
#   - the contract is THE struct embedding a runar base; others are ignored;
#   - zero or several such structs refuse the file;
#   - a method whose receiver (value or pointer) is another type refuses it;
#   - a free function, exported or not, is a private helper.
# Proves: this tier's .runar.go diagnostics and method set per shape.
# Does NOT prove: the other tiers, or anything on chain.
# ---------------------------------------------------------------------------

F010_PRELUDE = 'package contract\n\nimport runar "github.com/icellan/runar/packages/runar-go"\n'
F010_GUARDED = (
    "\ntype Guarded struct {\n\trunar.SmartContract\n\tPubKey runar.PubKey `runar:\"readonly\"`\n}\n"
    "\nfunc (c *Guarded) Unlock(sig runar.Sig) {\n\trunar.Assert(runar.CheckSig(sig, c.PubKey))\n}\n"
)
F010_RECEIVER_ERROR = (
    "method 'Drain' has receiver type 'Unrelated', not the contract type 'Guarded'; "
    "methods on other types are not allowed"
)


def _f010_unrelated(recv: str) -> str:
    return f"\ntype Unrelated struct{{}}\n\nfunc ({recv}) Drain(amount runar.Bigint) {{\n\trunar.Assert(true)\n}}\n"


def _f010_errors(src: str) -> list[str]:
    result = parse_source(src, "Guarded.runar.go")
    return [e.message for e in result.errors if e.severity == "error"]


def _f010_methods(src: str) -> list[str]:
    c = parse_source(src, "Guarded.runar.go").contract
    assert c is not None
    return [f"{m.name}({m.visibility})" for m in c.methods]


class TestF010ContractStructAndReceivers:
    @pytest.mark.parametrize(
        "src",
        [
            F010_PRELUDE + F010_GUARDED + _f010_unrelated("u Unrelated"),
            F010_PRELUDE + F010_GUARDED + _f010_unrelated("u *Unrelated"),
            F010_PRELUDE + _f010_unrelated("u Unrelated") + F010_GUARDED,
            F010_PRELUDE + _f010_unrelated("u *Unrelated") + F010_GUARDED,
            F010_PRELUDE + F010_GUARDED
            + "\nfunc (u Unrelated) Drain(amount runar.Bigint) {\n\trunar.Assert(true)\n}\n",
        ],
        ids=["value-after", "pointer-after", "value-before", "pointer-before", "undeclared-type"],
    )
    def test_foreign_receiver_refused(self, src):
        assert _f010_errors(src) == [F010_RECEIVER_ERROR]

    def test_contract_receivers_kept(self):
        src = F010_PRELUDE + F010_GUARDED + "\nfunc (c Guarded) Drain(amount runar.Bigint) {\n\trunar.Assert(amount > 0)\n}\n"
        assert _f010_errors(src) == []
        assert _f010_methods(src) == ["unlock(public)", "drain(public)"]

    def test_exported_free_function_is_private_helper(self):
        src = F010_PRELUDE + F010_GUARDED + "\nfunc Drain(amount runar.Bigint) {\n\trunar.Assert(true)\n}\n"
        assert _f010_errors(src) == []
        assert _f010_methods(src) == ["unlock(public)", "drain(private)"]

    def test_helper_struct_ignored(self):
        helper = "\ntype Helper struct {\n\tAmount runar.Bigint\n}\n"
        for src in (F010_PRELUDE + F010_GUARDED + helper, F010_PRELUDE + helper + F010_GUARDED):
            result = parse_source(src, "Guarded.runar.go")
            assert result.errors == [], result.error_strings()
            assert result.contract.name == "Guarded"
            assert [p.name for p in result.contract.properties] == ["pubKey"]

    def test_no_contract_struct(self):
        src = F010_PRELUDE + "\ntype Helper struct {\n\tAmount runar.Bigint\n}\n"
        assert _f010_errors(src) == ["no Rúnar contract struct found in Go source"]

    def test_two_contract_structs(self):
        src = F010_PRELUDE + F010_GUARDED + "\ntype Other struct {\n\trunar.StatefulSmartContract\n\tCount runar.Bigint\n}\n"
        assert _f010_errors(src) == [
            "multiple Rúnar contract structs found in Go source: 'Guarded' and 'Other'; "
            "exactly one struct may embed runar.SmartContract, runar.StatefulSmartContract "
            "or runar.UnsafeSmartContract"
        ]
