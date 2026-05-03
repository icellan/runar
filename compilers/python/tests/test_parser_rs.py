"""Tests for the .runar.rs parser — Python port of the Go reference
``parser_rustmacro_test.go``.

Pins a representative slice of the Rust proc-macro surface
(``#[runar::contract]``, ``#[readonly]``, ``#[public]``, ``&self`` exclusion)
so the Python parser's per-format behaviour is verified explicitly.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


P2PKH_SOURCE = """\
use runar::prelude::*;

#[runar::contract]
pub struct P2PKH {
    #[readonly]
    pub pub_key_hash: Addr,
}

#[runar::methods(P2PKH)]
impl P2PKH {
    #[public]
    pub fn unlock(&self, sig: &Sig, pub_key: &PubKey) {
        assert!(hash160(pub_key) == self.pub_key_hash);
        assert!(check_sig(sig, pub_key));
    }
}
"""


class TestRustP2PKH:
    def test_parses_to_expected_contract_shape(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.rs")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "P2PKH"
        # All properties readonly → SmartContract (stateless).
        assert c.parent_class == "SmartContract"
        assert len(c.properties) == 1
        prop = c.properties[0]
        assert prop.name == "pubKeyHash"
        assert prop.readonly is True

    def test_unlock_method_signature(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.rs")
        c = result.contract
        assert c is not None
        assert len(c.methods) == 1
        unlock = c.methods[0]
        assert unlock.name == "unlock"
        assert unlock.visibility == "public"
        # &self is excluded; sig and pub_key (camelCase) remain.
        names = [p.name for p in unlock.params]
        assert names == ["sig", "pubKey"]


class TestRustStateful:
    def test_mutable_property_implies_stateful(self):
        source = """\
use runar::prelude::*;

#[runar::contract]
pub struct Counter {
    pub count: Bigint,
}

#[runar::methods(Counter)]
impl Counter {
    #[public]
    pub fn increment(&mut self) {
        self.count += 1;
    }

    #[public]
    pub fn decrement(&mut self) {
        assert!(self.count > 0);
        self.count -= 1;
    }
}
"""
        result = parse_source(source, "Counter.runar.rs")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "Counter"
        # `count` not marked readonly → StatefulSmartContract.
        assert c.parent_class == "StatefulSmartContract"
        assert len(c.properties) == 1
        assert c.properties[0].name == "count"
        assert c.properties[0].readonly is False
        method_names = [m.name for m in c.methods]
        assert method_names == ["increment", "decrement"]
