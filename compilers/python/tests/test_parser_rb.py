"""Tests for the .runar.rb parser — Python port of the Go reference
``parser_ruby_test.go``.

Pins a representative slice of the Ruby surface (`prop`, `runar_public`,
`@ivar` initialisation, snake_case to camelCase mapping, stateful contract
detection).
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source


P2PKH_SOURCE = """\
require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
"""


class TestRubyP2PKH:
    def test_parses_to_expected_contract_shape(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "P2PKH"
        assert c.parent_class == "SmartContract"

        # Snake_case `pub_key_hash` -> camelCase `pubKeyHash`.
        assert len(c.properties) == 1
        prop = c.properties[0]
        assert prop.name == "pubKeyHash"
        # Stateless contract → property is readonly.
        assert prop.readonly is True

    def test_unlock_method_signature(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.rb")
        c = result.contract
        assert c is not None
        assert len(c.methods) == 1
        m = c.methods[0]
        assert m.name == "unlock"
        assert m.visibility == "public"
        assert [p.name for p in m.params] == ["sig", "pubKey"]


class TestRubyStateful:
    def test_stateful_counter(self):
        source = """\
require 'runar'

class Counter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public
  def increment
    @count += 1
  end

  runar_public
  def decrement
    assert @count > 0
    @count -= 1
  end
end
"""
        result = parse_source(source, "Counter.runar.rb")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "Counter"
        assert c.parent_class == "StatefulSmartContract"
        # Mutable in stateful contract: not readonly.
        assert len(c.properties) == 1
        assert c.properties[0].readonly is False
        method_names = [m.name for m in c.methods]
        assert method_names == ["increment", "decrement"]
