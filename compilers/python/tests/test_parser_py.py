"""Tests for the .runar.py parser — Python port of the Go reference
``parser_python_test.go``.

These tests pin a representative slice of the Python surface (snake_case to
camelCase mapping, ``Readonly[T]``, ``@public``, ``self`` exclusion,
``StatefulSmartContract``).
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


P2PKH_SOURCE = """\
from runar import SmartContract, assert_, hash160, check_sig, Addr, Sig, PubKey
from typing import Readonly

class P2PKH(SmartContract):
    pub_key_hash: Readonly[Addr]

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
"""


class TestPyP2PKH:
    def test_snake_to_camel_property(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.py")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "P2PKH"
        assert c.parent_class == "SmartContract"

        assert len(c.properties) >= 1
        assert c.properties[0].name == "pubKeyHash"

    def test_self_excluded_from_method_params(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.py")
        c = result.contract
        assert c is not None
        unlock = next(m for m in c.methods if m.name == "unlock")
        # `self` must not appear in the params.
        assert all(p.name != "self" for p in unlock.params)
        # Snake-case `pub_key` should be camelCase'd.
        assert "pubKey" in [p.name for p in unlock.params]


class TestPyMethodVisibility:
    def test_method_visibility_public(self):
        source = """\
from runar import SmartContract, assert_

class Adder(SmartContract):
    target: int

    def __init__(self, target: int):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, a: int, b: int):
        assert_(a + b == self.target)
"""
        result = parse_source(source, "Adder.runar.py")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert len(c.methods) == 1
        m = c.methods[0]
        assert m.name == "verify"
        assert m.visibility == "public"


class TestPyStateful:
    def test_stateful_counter(self):
        source = """\
from runar import StatefulSmartContract

class Counter(StatefulSmartContract):
    count: int

    def __init__(self, count: int):
        super().__init__(count)
        self.count = count

    @public
    def increment(self):
        self.count = self.count + 1
"""
        result = parse_source(source, "Counter.runar.py")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "Counter"
        assert c.parent_class == "StatefulSmartContract"


class TestPySnakeToCamelMethodName:
    def test_method_name_becomes_camel(self):
        source = """\
from runar import SmartContract, assert_, hash160, Addr, PubKey
from typing import Readonly

class HashCheck(SmartContract):
    pub_key_hash: Readonly[Addr]

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def check_hash(self, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
"""
        result = parse_source(source, "HashCheck.runar.py")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert len(c.properties) >= 1
        assert c.properties[0].name == "pubKeyHash"
        assert len(c.methods) >= 1
        assert c.methods[0].name == "checkHash"


class TestPyRejection:
    def test_invalid_syntax_produces_error(self):
        source = "class (SmartContract):\n    pass\n"
        result = parse_source(source, "bad.runar.py")
        assert result.contract is None or len(result.errors) > 0
