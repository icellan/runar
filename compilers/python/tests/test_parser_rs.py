"""Tests for the .runar.rs parser — Python port of the Go reference
``parser_rustmacro_test.go``.

Pins a representative slice of the Rust contract surface
(``#[runar::contract]``, ``#[readonly]``, bare ``impl`` blocks, ``pub fn`` vs
``fn`` visibility, ``&self`` exclusion) so the Python parser's per-format
behaviour is verified explicitly.
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

impl P2PKH {
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

impl Counter {
    pub fn increment(&mut self) {
        self.count += 1;
    }

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


class TestRustBareImpl:
    def test_bare_impl_without_methods_attribute(self):
        source = """\
use runar::prelude::*;

#[runar::contract]
pub struct Counter {
    pub count: Bigint,
}

impl Counter {
    pub fn increment(&mut self) {
        self.count += 1;
    }

    fn helper(&self) {
        assert!(self.count > 0);
    }
}
"""
        result = parse_source(source, "Counter.runar.rs")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert [m.name for m in c.methods] == ["increment", "helper"]
        assert c.methods[0].visibility == "public"
        assert c.methods[1].visibility == "private"

    def test_multiple_impl_blocks_merge_in_order(self):
        source = """\
use runar::prelude::*;

#[runar::contract]
pub struct Multi {
    #[readonly]
    pub x: Bigint,
}

impl Multi {
    pub fn first(&self) {
        assert!(self.x > 0);
    }
}

impl Multi {
    pub fn second(&self) {
        assert!(self.x < 100);
    }
}
"""
        result = parse_source(source, "Multi.runar.rs")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert [m.name for m in c.methods] == ["first", "second"]

    def test_impl_before_struct(self):
        source = """\
use runar::prelude::*;

impl Early {
    pub fn check(&self) {
        assert!(self.x > 0);
    }
}

#[runar::contract]
pub struct Early {
    #[readonly]
    pub x: Bigint,
}
"""
        result = parse_source(source, "Early.runar.rs")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "Early"
        assert [m.name for m in c.methods] == ["check"]


class TestRustRemovedSpellings:
    def test_runar_methods_attribute_rejected(self):
        source = """\
use runar::prelude::*;

#[runar::contract]
pub struct Old {
    #[readonly]
    pub x: Bigint,
}

#[runar::methods(Old)]
impl Old {
    pub fn check(&self) {
        assert!(self.x > 0);
    }
}
"""
        result = parse_source(source, "Old.runar.rs")
        assert any("#[runar::methods]" in e for e in result.error_strings()), result.error_strings()

    def test_public_attribute_rejected(self):
        source = """\
use runar::prelude::*;

#[runar::contract]
pub struct Old {
    #[readonly]
    pub x: Bigint,
}

impl Old {
    #[public]
    pub fn check(&self) {
        assert!(self.x > 0);
    }
}
"""
        result = parse_source(source, "Old.runar.rs")
        assert any("#[public]" in e for e in result.error_strings()), result.error_strings()
