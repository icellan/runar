"""Tests for the .runar.ts parser (Python port of the authoritative TypeScript
parser surface spec).

Each test sanity-checks a specific slice of the TypeScript subset that the
parser must accept or reject — paralleling the Go reference
``parser_*_test.go`` files and the other format-parity tests in this
directory.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


# ---------------------------------------------------------------------------
# P2PKH — the reference stateless contract used everywhere.
# ---------------------------------------------------------------------------

P2PKH_SOURCE = """\
import { SmartContract, assert, hash160, checkSig } from 'runar-lang';

export class P2PKH extends SmartContract {
    readonly pubKeyHash: ByteString;

    constructor(pubKeyHash: ByteString) {
        super(pubKeyHash);
    }

    public unlock(sig: Sig, pubKey: PubKey) {
        assert(hash160(pubKey) == this.pubKeyHash);
        assert(checkSig(sig, pubKey));
    }
}
"""


class TestTsP2PKH:
    def test_parses_to_expected_contract_shape(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.ts")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "P2PKH"
        assert c.parent_class == "SmartContract"

        assert len(c.properties) == 1
        prop = c.properties[0]
        assert prop.name == "pubKeyHash"
        assert prop.readonly is True

    def test_unlock_method_params(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.ts")
        c = result.contract
        assert c is not None
        unlock = next(m for m in c.methods if m.name == "unlock")
        assert unlock.visibility == "public"
        assert [p.name for p in unlock.params] == ["sig", "pubKey"]


# ---------------------------------------------------------------------------
# Counter — stateful contract.
# ---------------------------------------------------------------------------

COUNTER_SOURCE = """\
import { StatefulSmartContract } from 'runar-lang';

export class Counter extends StatefulSmartContract {
    count: bigint;

    constructor(count: bigint) {
        super(count);
        this.count = count;
    }

    public increment() {
        this.count = this.count + 1n;
    }

    public decrement() {
        assert(this.count > 0n);
        this.count = this.count - 1n;
    }
}
"""


class TestTsCounter:
    def test_parses_stateful_contract(self):
        result = parse_source(COUNTER_SOURCE, "Counter.runar.ts")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "Counter"
        assert c.parent_class == "StatefulSmartContract"

        # Mutable property in stateful contract.
        assert len(c.properties) == 1
        assert c.properties[0].name == "count"
        assert c.properties[0].readonly is False

        method_names = [m.name for m in c.methods]
        assert "increment" in method_names
        assert "decrement" in method_names


# ---------------------------------------------------------------------------
# Rejection / dispatch sanity tests.
# ---------------------------------------------------------------------------


class TestTsDispatch:
    def test_unknown_extension_returns_error(self):
        result = parse_source("class Foo {}", "Foo.txt")
        assert result.contract is None
        assert len(result.errors) == 1

    def test_extension_match_is_case_insensitive(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.RUNAR.TS")
        assert result.errors == [], result.error_strings()
        assert result.contract is not None
        assert result.contract.name == "P2PKH"
