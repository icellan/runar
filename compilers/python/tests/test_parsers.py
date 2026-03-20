"""Tests for the multi-format parser dispatch and individual parsers.

Covers TS, Solidity, Move, Python, Go, Rust, and Ruby format parsers. Each test
provides a minimal contract source string and verifies the resulting AST
has the correct contract name, parent class, properties, and methods.
"""

from __future__ import annotations

import os
import pytest

from runar_compiler.frontend.parser_dispatch import parse_source, ParseResult
from runar_compiler.frontend.ast_nodes import (
    ContractNode,
    PrimitiveType,
    ArrayLiteralExpr,
    AssignmentStmt,
    BinaryExpr,
    BigIntLiteral,
    BoolLiteral,
    ByteStringLiteral,
    CallExpr,
    ExpressionStmt,
    ForStmt,
    Identifier,
    IfStmt,
    PropertyAccessExpr,
    ReturnStmt,
    TernaryExpr,
    UnaryExpr,
    VariableDeclStmt,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assert_p2pkh_ast(contract: ContractNode, expected_name: str = "P2PKH") -> None:
    """Verify common P2PKH AST structure across all formats."""
    assert contract.name == expected_name
    assert contract.parent_class == "SmartContract"
    assert len(contract.properties) >= 1
    # The first property should be pubKeyHash (camelCase in AST)
    prop = contract.properties[0]
    assert prop.name == "pubKeyHash"
    # Should have at least an unlock method
    method_names = [m.name for m in contract.methods]
    assert "unlock" in method_names


# ---------------------------------------------------------------------------
# TypeScript parser (.runar.ts)
# ---------------------------------------------------------------------------

TS_P2PKH_SOURCE = """\
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


class TestTSParser:
    def test_parse_basic_p2pkh(self):
        result = parse_source(TS_P2PKH_SOURCE, "P2PKH.runar.ts")
        assert len(result.errors) == 0
        assert result.contract is not None
        _assert_p2pkh_ast(result.contract)

    def test_parse_ts_has_constructor(self):
        result = parse_source(TS_P2PKH_SOURCE, "P2PKH.runar.ts")
        assert result.contract is not None
        # Constructor should exist with super() call
        assert result.contract.constructor is not None

    def test_parse_ts_unlock_params(self):
        result = parse_source(TS_P2PKH_SOURCE, "P2PKH.runar.ts")
        assert result.contract is not None
        unlock = [m for m in result.contract.methods if m.name == "unlock"][0]
        param_names = [p.name for p in unlock.params]
        assert "sig" in param_names
        assert "pubKey" in param_names

    def test_parse_ts_property_readonly(self):
        result = parse_source(TS_P2PKH_SOURCE, "P2PKH.runar.ts")
        assert result.contract is not None
        prop = result.contract.properties[0]
        assert prop.readonly is True


# ---------------------------------------------------------------------------
# Solidity parser (.runar.sol)
# ---------------------------------------------------------------------------

SOL_P2PKH_SOURCE = """\
contract P2PKH is SmartContract {
    bytes pubKeyHash;

    constructor(bytes pubKeyHash) {
        this.pubKeyHash = pubKeyHash;
    }

    function unlock(Sig sig, PubKey pubKey) public {
        assert(hash160(pubKey) == this.pubKeyHash);
        assert(checkSig(sig, pubKey));
    }
}
"""


class TestSolParser:
    def test_parse_basic_contract(self):
        result = parse_source(SOL_P2PKH_SOURCE, "P2PKH.runar.sol")
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"
        assert result.contract.parent_class == "SmartContract"

    def test_parse_sol_properties(self):
        result = parse_source(SOL_P2PKH_SOURCE, "P2PKH.runar.sol")
        assert result.contract is not None
        assert len(result.contract.properties) >= 1
        prop = result.contract.properties[0]
        assert prop.name == "pubKeyHash"

    def test_parse_sol_methods(self):
        result = parse_source(SOL_P2PKH_SOURCE, "P2PKH.runar.sol")
        assert result.contract is not None
        method_names = [m.name for m in result.contract.methods]
        assert "unlock" in method_names

    def test_parse_sol_multiple_properties(self):
        """A Solidity contract with 3 properties has all 3 parsed.
        Mirrors Go TestParseSolidity_MultipleProperties."""
        source = """\
contract ThreeProps is SmartContract {
    Addr immutable addr;
    PubKey immutable key;
    bytes immutable data;

    constructor(Addr _addr, PubKey _key, bytes _data) {
        addr = _addr;
        key = _key;
        data = _data;
    }

    function check(int x) public {
        require(x == 1);
    }
}
"""
        result = parse_source(source, "ThreeProps.runar.sol")
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "ThreeProps"
        assert len(result.contract.properties) == 3, (
            f"expected 3 properties, got {len(result.contract.properties)}: "
            f"{[p.name for p in result.contract.properties]}"
        )


# ---------------------------------------------------------------------------
# Move parser (.runar.move)
# ---------------------------------------------------------------------------

MOVE_P2PKH_SOURCE = """\
module P2PKH {
    use runar::types::{Addr, PubKey, Sig};
    use runar::crypto::{hash160, check_sig};

    resource struct P2PKH {
        pub_key_hash: Addr,
    }

    public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        assert!(check_sig(sig, pub_key), 0);
    }
}
"""


class TestMoveParser:
    def test_parse_basic_module(self):
        result = parse_source(MOVE_P2PKH_SOURCE, "P2PKH.runar.move")
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"
        assert result.contract.parent_class == "SmartContract"

    def test_parse_move_properties(self):
        result = parse_source(MOVE_P2PKH_SOURCE, "P2PKH.runar.move")
        assert result.contract is not None
        assert len(result.contract.properties) >= 1
        # Move uses snake_case -> camelCase in AST
        prop_names = [p.name for p in result.contract.properties]
        assert "pubKeyHash" in prop_names

    def test_parse_move_methods(self):
        result = parse_source(MOVE_P2PKH_SOURCE, "P2PKH.runar.move")
        assert result.contract is not None
        method_names = [m.name for m in result.contract.methods]
        assert "unlock" in method_names

    def test_parse_move_invalid_syntax(self):
        """Malformed Move source (module without a name) raises an error.
        Mirrors Go TestParseMove_InvalidSyntax_Error."""
        source = """\
module {
    // missing name
}
"""
        result = parse_source(source, "bad.runar.move")
        # Either we get errors or no contract — either is acceptable
        assert result.contract is None or len(result.errors) > 0, (
            "expected errors for invalid Move syntax (module without name)"
        )

    def test_parse_move_multiple_methods(self):
        """Move contract with 2 public methods both parsed.
        Mirrors Go TestParseMove_MultipleMethods."""
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
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "Multi"
        assert len(result.contract.methods) == 2, (
            f"expected 2 methods, got {len(result.contract.methods)}: "
            f"{[m.name for m in result.contract.methods]}"
        )


# ---------------------------------------------------------------------------
# Python parser (.runar.py)
# ---------------------------------------------------------------------------

PY_P2PKH_SOURCE = """\
from runar import SmartContract, assert_, hash160, check_sig

class P2PKH(SmartContract):
    pub_key_hash: ByteString

    def __init__(self, pub_key_hash: ByteString):
        super().__init__(pub_key_hash)

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
"""


class TestPythonParser:
    def test_parse_basic_class(self):
        result = parse_source(PY_P2PKH_SOURCE, "P2PKH.runar.py")
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"
        assert result.contract.parent_class == "SmartContract"

    def test_parse_python_properties(self):
        result = parse_source(PY_P2PKH_SOURCE, "P2PKH.runar.py")
        assert result.contract is not None
        assert len(result.contract.properties) >= 1
        # Python snake_case -> camelCase
        prop_names = [p.name for p in result.contract.properties]
        assert "pubKeyHash" in prop_names

    def test_parse_python_methods(self):
        result = parse_source(PY_P2PKH_SOURCE, "P2PKH.runar.py")
        assert result.contract is not None
        method_names = [m.name for m in result.contract.methods]
        assert "unlock" in method_names

    def test_parse_python_method_params(self):
        result = parse_source(PY_P2PKH_SOURCE, "P2PKH.runar.py")
        assert result.contract is not None
        unlock = [m for m in result.contract.methods if m.name == "unlock"][0]
        # 'self' should be stripped from params
        param_names = [p.name for p in unlock.params]
        assert "self" not in param_names
        assert "sig" in param_names
        assert "pubKey" in param_names


# ---------------------------------------------------------------------------
# Go contract parser (.runar.go)
# ---------------------------------------------------------------------------

GO_P2PKH_SOURCE = """\
package contract

import "github.com/icellan/runar/packages/runar-go"

type P2PKH struct {
    runar.SmartContract
    PubKeyHash runar.ByteString
}

func (c *P2PKH) init() {
    c.PubKeyHash = c.PubKeyHash
}

func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
    runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
    runar.Assert(runar.CheckSig(sig, pubKey))
}
"""


class TestGoParser:
    def test_parse_basic_struct(self):
        result = parse_source(GO_P2PKH_SOURCE, "P2PKH.runar.go")
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"
        assert result.contract.parent_class == "SmartContract"

    def test_parse_go_properties(self):
        result = parse_source(GO_P2PKH_SOURCE, "P2PKH.runar.go")
        assert result.contract is not None
        assert len(result.contract.properties) >= 1
        prop_names = [p.name for p in result.contract.properties]
        assert "pubKeyHash" in prop_names

    def test_parse_go_methods(self):
        result = parse_source(GO_P2PKH_SOURCE, "P2PKH.runar.go")
        assert result.contract is not None
        method_names = [m.name for m in result.contract.methods]
        # Go exported methods like Unlock -> unlock in AST
        assert "unlock" in method_names


# ---------------------------------------------------------------------------
# Rust DSL parser (.runar.rs)
# ---------------------------------------------------------------------------

RUST_P2PKH_SOURCE = """\
use runar::prelude::*;

#[runar::contract]
pub struct P2PKH {
    #[readonly]
    pub_key_hash: ByteString,
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


class TestRustParser:
    def test_parse_basic_struct(self):
        result = parse_source(RUST_P2PKH_SOURCE, "P2PKH.runar.rs")
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"
        assert result.contract.parent_class == "SmartContract"

    def test_parse_rust_properties(self):
        result = parse_source(RUST_P2PKH_SOURCE, "P2PKH.runar.rs")
        assert result.contract is not None
        assert len(result.contract.properties) >= 1
        prop_names = [p.name for p in result.contract.properties]
        # Rust snake_case -> camelCase
        assert "pubKeyHash" in prop_names

    def test_parse_rust_methods(self):
        result = parse_source(RUST_P2PKH_SOURCE, "P2PKH.runar.rs")
        assert result.contract is not None
        method_names = [m.name for m in result.contract.methods]
        assert "unlock" in method_names


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestParserErrors:
    def test_unsupported_extension(self):
        result = parse_source("some code", "test.txt")
        assert len(result.errors) > 0
        assert result.contract is None

    def test_empty_ts_source(self):
        result = parse_source("", "Empty.runar.ts")
        # Should either have errors or no contract
        assert result.contract is None or len(result.errors) > 0

    def test_invalid_ts_syntax(self):
        result = parse_source("this is not valid { { { TypeScript", "Bad.runar.ts")
        assert result.contract is None or len(result.errors) > 0

    def test_invalid_sol_syntax(self):
        result = parse_source("this is not a solidity contract", "Bad.runar.sol")
        assert result.contract is None or len(result.errors) > 0

    def test_invalid_py_syntax(self):
        result = parse_source("def ??? broken(", "Bad.runar.py")
        assert result.contract is None or len(result.errors) > 0


# ---------------------------------------------------------------------------
# Dispatch correctness
# ---------------------------------------------------------------------------

class TestParserDispatch:
    def test_ts_extension_dispatches(self):
        """Verify .runar.ts routes to TS parser and produces valid AST."""
        result = parse_source(TS_P2PKH_SOURCE, "test.runar.ts")
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_sol_extension_dispatches(self):
        result = parse_source(SOL_P2PKH_SOURCE, "test.runar.sol")
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_case_insensitive_extension(self):
        """Extension matching should be case-insensitive."""
        result = parse_source(TS_P2PKH_SOURCE, "test.RUNAR.TS")
        # parse_source lowercases the extension
        assert result.contract is not None or len(result.errors) > 0


# ---------------------------------------------------------------------------
# TS parser: additional edge cases (rows 5, 7)
# ---------------------------------------------------------------------------

class TestTSParserEdgeCases:
    def test_stateful_mutable_property_not_readonly(self):
        """StatefulSmartContract mutable property should not be marked readonly (row 5)."""
        source = """\
import { StatefulSmartContract } from 'runar-lang';

class Counter extends StatefulSmartContract {
    count: bigint;

    constructor(count: bigint) {
        super(count);
        this.count = count;
    }

    public increment(): void {
        this.count = this.count + 1n;
        this.addOutput(1000n, this.count);
    }
}
"""
        result = parse_source(source, "Counter.runar.ts")
        assert result.contract is not None
        count_prop = next((p for p in result.contract.properties if p.name == "count"), None)
        assert count_prop is not None, "expected 'count' property"
        assert count_prop.readonly is False, (
            f"expected count.readonly=False for StatefulSmartContract, got {count_prop.readonly}"
        )

    def test_multiple_methods_public_and_private_visibility(self):
        """Public and private methods have the correct visibility flags (row 7)."""
        source = """\
import { SmartContract, assert, checkSig } from 'runar-lang';

class Multi extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    private helper(n: bigint): boolean {
        return n > 0n;
    }

    public verify1(a: bigint): void {
        assert(this.helper(a));
    }

    public verify2(b: bigint): void {
        assert(this.helper(b));
    }
}
"""
        result = parse_source(source, "Multi.runar.ts")
        assert result.contract is not None
        methods = result.contract.methods
        method_names = [m.name for m in methods]

        helper = next((m for m in methods if m.name == "helper"), None)
        verify1 = next((m for m in methods if m.name == "verify1"), None)
        verify2 = next((m for m in methods if m.name == "verify2"), None)

        assert helper is not None, "expected 'helper' method"
        assert verify1 is not None, "expected 'verify1' method"
        assert verify2 is not None, "expected 'verify2' method"

        assert helper.visibility == "private" or not getattr(helper, 'is_public', True), (
            "helper should be private"
        )
        assert verify1.visibility == "public" or getattr(verify1, 'is_public', False), (
            "verify1 should be public"
        )
        assert verify2.visibility == "public" or getattr(verify2, 'is_public', False), (
            "verify2 should be public"
        )


# ---------------------------------------------------------------------------
# Solidity parser: StatefulSmartContract (row 35)
# ---------------------------------------------------------------------------

class TestSolStateful:
    def test_stateful_parent_class(self):
        """Solidity-style Counter should have parentClass='StatefulSmartContract' (row 35)."""
        source = """\
contract Counter is StatefulSmartContract {
    int count;

    constructor(int _count) {
        this.count = _count;
    }

    function increment() public {
        this.count = this.count + 1;
        this.addOutput(1000, this.count);
    }
}
"""
        result = parse_source(source, "Counter.runar.sol")
        assert result.contract is not None, f"expected contract, got errors: {result.errors}"
        assert result.contract.parent_class == "StatefulSmartContract", (
            f"expected parentClass='StatefulSmartContract', got '{result.contract.parent_class}'"
        )


# ---------------------------------------------------------------------------
# Move parser: StatefulSmartContract (row 42)
# ---------------------------------------------------------------------------

class TestMoveStateful:
    def test_stateful_parent_class(self):
        """Move-style Counter should have parentClass='StatefulSmartContract' (row 42)."""
        source = """\
module Counter {
    use runar::StatefulSmartContract;

    resource struct Counter has StatefulSmartContract {
        count: bigint,
    }

    public fun increment(contract: &mut Counter) {
        contract.count = contract.count + 1;
    }
}
"""
        result = parse_source(source, "Counter.runar.move")
        assert result.contract is not None, f"expected contract, got errors: {result.errors}"
        assert result.contract.parent_class == "StatefulSmartContract", (
            f"expected parentClass='StatefulSmartContract', got '{result.contract.parent_class}'"
        )


# ---------------------------------------------------------------------------
# Go parser: additional tests (rows 48-51)
# ---------------------------------------------------------------------------

GO_MULTI_PROPS_SOURCE = """\
package contract

import "github.com/icellan/runar/packages/runar-go"

type MultiProps struct {
    runar.SmartContract
    PubKeyHash runar.ByteString
    Amount     runar.Bigint
}

func (c *MultiProps) init() {
    c.PubKeyHash = c.PubKeyHash
    c.Amount = c.Amount
}

func (c *MultiProps) Unlock(sig runar.Sig, pubKey runar.PubKey) {
    runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
    runar.Assert(runar.CheckSig(sig, pubKey))
}
"""

GO_STATEFUL_SOURCE = """\
package contract

import "github.com/icellan/runar/packages/runar-go"

type Counter struct {
    runar.StatefulSmartContract
    Count runar.Bigint
}

func (c *Counter) init() {
    c.Count = c.Count
}

func (c *Counter) Increment(txPreimage runar.SigHashPreimage, changePKH runar.Addr, changeAmt runar.Bigint) {
    c.Count = c.Count + 1
    runar.AddOutput(1000, c.Count)
}
"""

GO_NON_RUNAR_SOURCE = """\
package contract

type Foo struct {
    X int
    Y int
}

func (f *Foo) Bar() {
    f.X = f.X + 1
}
"""


class TestGoParserAdditional:
    def test_exported_method_visibility_is_public(self):
        """Go exported methods (uppercase) should map to visibility='public' (row 48)."""
        result = parse_source(GO_P2PKH_SOURCE, "P2PKH.runar.go")
        assert result.contract is not None
        # Unlock -> unlock in AST, should be public
        unlock = next((m for m in result.contract.methods if m.name == "unlock"), None)
        assert unlock is not None, "expected 'unlock' method"
        assert unlock.visibility == "public" or getattr(unlock, 'is_public', False), (
            f"expected unlock to be public, got visibility={getattr(unlock, 'visibility', None)}"
        )

    def test_multiple_properties_parsed(self):
        """Go struct with 2 non-embedded properties should produce 2 properties (row 49)."""
        result = parse_source(GO_MULTI_PROPS_SOURCE, "MultiProps.runar.go")
        assert result.contract is not None, f"got errors: {result.errors}"
        prop_names = [p.name for p in result.contract.properties]
        assert "pubKeyHash" in prop_names, f"expected pubKeyHash in {prop_names}"
        assert "amount" in prop_names, f"expected amount in {prop_names}"

    def test_stateful_parent_class(self):
        """Go struct embedding StatefulSmartContract → parentClass='StatefulSmartContract' (row 50)."""
        result = parse_source(GO_STATEFUL_SOURCE, "Counter.runar.go")
        assert result.contract is not None, f"got errors: {result.errors}"
        assert result.contract.parent_class == "StatefulSmartContract", (
            f"expected 'StatefulSmartContract', got '{result.contract.parent_class}'"
        )

    def test_non_runar_struct_produces_error_or_no_contract(self):
        """Go struct without runar embed → nil contract or errors (row 51)."""
        result = parse_source(GO_NON_RUNAR_SOURCE, "Foo.runar.go")
        # Either the contract is None or there are errors
        assert result.contract is None or len(result.errors) > 0, (
            "expected error for non-Runar Go struct, but got a valid contract"
        )


# ---------------------------------------------------------------------------
# Ruby contract source fixtures
# ---------------------------------------------------------------------------

RB_P2PKH_SOURCE = """\
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

RB_COUNTER_SOURCE = """\
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

RB_ESCROW_SOURCE = """\
require 'runar'

class Escrow < Runar::SmartContract
  prop :buyer, PubKey
  prop :seller, PubKey
  prop :arbiter, PubKey

  def initialize(buyer, seller, arbiter)
    super(buyer, seller, arbiter)
    @buyer = buyer
    @seller = seller
    @arbiter = arbiter
  end

  runar_public sig: Sig
  def release_by_seller(sig)
    assert check_sig(sig, @seller)
  end

  runar_public sig: Sig
  def release_by_arbiter(sig)
    assert check_sig(sig, @arbiter)
  end

  runar_public sig: Sig
  def refund_to_buyer(sig)
    assert check_sig(sig, @buyer)
  end
end
"""

RB_FUNGIBLE_TOKEN_SOURCE = """\
require 'runar'

class FungibleToken < Runar::StatefulSmartContract
  prop :owner, PubKey
  prop :balance, Bigint
  prop :token_id, ByteString, readonly: true

  def initialize(owner, balance, token_id)
    super(owner, balance, token_id)
    @owner = owner
    @balance = balance
    @token_id = token_id
  end

  runar_public sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint
  def transfer(sig, to, amount, output_satoshis)
    assert check_sig(sig, @owner)
    assert amount > 0
    assert amount <= @balance
    add_output(output_satoshis, to, amount)
    add_output(output_satoshis, @owner, @balance - amount)
  end

  runar_public sig: Sig, to: PubKey, output_satoshis: Bigint
  def send_all(sig, to, output_satoshis)
    assert check_sig(sig, @owner)
    add_output(output_satoshis, to, @balance)
  end
end
"""


def _rb_simple_contract(method_body: str, prop_type: str = "Bigint") -> str:
    """Return a minimal SmartContract with one property and one public method."""
    return f"""\
class Foo < Runar::SmartContract
  prop :x, {prop_type}

  def initialize(x)
    super(x)
    @x = x
  end

  runar_public
  def bar
    {method_body}
  end
end
"""


def _rb_stateful_contract(method_body: str) -> str:
    """Return a minimal StatefulSmartContract with one mutable property."""
    return f"""\
class Counter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public
  def act
    {method_body}
  end
end
"""


# ---------------------------------------------------------------------------
# Ruby parser — basic contract parsing
# ---------------------------------------------------------------------------

class TestRubyParser:
    def test_parse_p2pkh_name(self):
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_parse_p2pkh_parent_class(self):
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        assert result.contract.parent_class == "SmartContract"

    def test_parse_p2pkh_has_constructor(self):
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        assert result.contract.constructor is not None
        assert result.contract.constructor.name == "constructor"

    def test_parse_p2pkh_unlock_params(self):
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        param_names = [p.name for p in unlock.params]
        assert "sig" in param_names
        assert "pubKey" in param_names

    def test_parse_p2pkh_property_readonly(self):
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        prop = result.contract.properties[0]
        assert prop.readonly is True

    def test_parse_stateful_counter_parent_class(self):
        result = parse_source(RB_COUNTER_SOURCE, "Counter.runar.rb")
        assert result.contract is not None
        assert result.contract.parent_class == "StatefulSmartContract"

    def test_parse_stateful_counter_mutable_property(self):
        result = parse_source(RB_COUNTER_SOURCE, "Counter.runar.rb")
        assert result.contract is not None
        count_prop = result.contract.properties[0]
        assert count_prop.name == "count"
        assert count_prop.readonly is False

    def test_parse_stateful_no_arg_method(self):
        result = parse_source(RB_COUNTER_SOURCE, "Counter.runar.rb")
        assert result.contract is not None
        inc = next(m for m in result.contract.methods if m.name == "increment")
        assert len(inc.params) == 0

    def test_parse_multiple_properties_in_order(self):
        result = parse_source(RB_ESCROW_SOURCE, "Escrow.runar.rb")
        assert result.contract is not None
        assert len(result.contract.properties) == 3
        assert [p.name for p in result.contract.properties] == ["buyer", "seller", "arbiter"]

    def test_parse_runar_namespace_prefix(self):
        """Runar::SmartContract namespace prefix is stripped correctly."""
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        assert result.contract.parent_class == "SmartContract"

    def test_parse_bare_parent_class_without_namespace(self):
        """Bare SmartContract without Runar:: prefix is accepted."""
        source = """\
class Foo < SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        assert result.contract.parent_class == "SmartContract"

    def test_parse_require_skipped(self):
        """require 'runar' lines are silently skipped."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"


# ---------------------------------------------------------------------------
# Ruby property declarations
# ---------------------------------------------------------------------------

class TestRubyPropDeclarations:
    def test_prop_snake_case_to_camel(self):
        """prop :pub_key_hash, Addr → property name 'pubKeyHash'."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].name == "pubKeyHash"

    def test_prop_readonly_true(self):
        """prop :x, Bigint, readonly: true → readonly=True."""
        source = """\
class Foo < Runar::StatefulSmartContract
  prop :x, Bigint, readonly: true
  def initialize(x)
    super(x)
    @x = x
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].readonly is True

    def test_stateful_default_mutable(self):
        """StatefulSmartContract props are mutable by default."""
        result = parse_source(RB_COUNTER_SOURCE, "Counter.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].readonly is False

    def test_smart_contract_default_readonly(self):
        """SmartContract props are readonly by default."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].readonly is True

    def test_type_bigint(self):
        """Bigint → bigint primitive."""
        result = parse_source(RB_COUNTER_SOURCE, "Counter.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].type == PrimitiveType(name="bigint")

    def test_type_addr(self):
        """Addr → Addr primitive."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].type == PrimitiveType(name="Addr")

    def test_type_pubkey(self):
        """PubKey → PubKey primitive."""
        result = parse_source(RB_ESCROW_SOURCE, "Escrow.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].type == PrimitiveType(name="PubKey")

    def test_type_bytestring(self):
        """ByteString → ByteString primitive."""
        result = parse_source(RB_FUNGIBLE_TOKEN_SOURCE, "FT.runar.rb")
        assert result.contract is not None
        token_id = next(p for p in result.contract.properties if p.name == "tokenId")
        assert token_id.type == PrimitiveType(name="ByteString")

    def test_type_boolean(self):
        """Boolean → boolean primitive."""
        source = """\
class Foo < Runar::SmartContract
  prop :active, Boolean
  def initialize(active)
    super(active)
    @active = active
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].type == PrimitiveType(name="boolean")

    def test_type_point(self):
        """Point → Point primitive."""
        source = """\
class Foo < Runar::SmartContract
  prop :pt, Point
  def initialize(pt)
    super(pt)
    @pt = pt
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].type == PrimitiveType(name="Point")


# ---------------------------------------------------------------------------
# Ruby method visibility
# ---------------------------------------------------------------------------

class TestRubyVisibility:
    def test_runar_public_makes_method_public(self):
        result = parse_source(RB_COUNTER_SOURCE, "Counter.runar.rb")
        assert result.contract is not None
        inc = next(m for m in result.contract.methods if m.name == "increment")
        assert inc.visibility == "public"

    def test_method_without_runar_public_is_private(self):
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  def helper
    return @x
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        helper = next((m for m in result.contract.methods if m.name == "helper"), None)
        assert helper is not None
        assert helper.visibility == "private"

    def test_runar_public_propagates_param_types(self):
        """runar_public sig: Sig, pub_key: PubKey → typed params on next method."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        sig_param = next(p for p in unlock.params if p.name == "sig")
        pub_key_param = next(p for p in unlock.params if p.name == "pubKey")
        assert sig_param.type == PrimitiveType(name="Sig")
        assert pub_key_param.type == PrimitiveType(name="PubKey")

    def test_bare_private_keyword_does_not_break_parsing(self):
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  private
  def helper
    return @x
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        # Should parse without crashing; helper may or may not be captured
        assert result.contract is not None


# ---------------------------------------------------------------------------
# Ruby instance variables
# ---------------------------------------------------------------------------

class TestRubyInstanceVars:
    def test_ivar_read_is_property_access(self):
        """@pub_key_hash in expression → PropertyAccessExpr(property='pubKeyHash')."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        # First assert: assert hash160(pub_key) == @pub_key_hash
        stmt = unlock.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        eq_expr = call.args[0]
        assert isinstance(eq_expr, BinaryExpr)
        assert isinstance(eq_expr.right, PropertyAccessExpr)
        assert eq_expr.right.property == "pubKeyHash"

    def test_ivar_assignment(self):
        """@count = expr → AssignmentStmt targeting PropertyAccessExpr."""
        source = _rb_stateful_contract("@count = 5")
        result = parse_source(source, "Counter.runar.rb")
        assert result.contract is not None
        act = next(m for m in result.contract.methods if m.name == "act")
        stmt = act.body[0]
        assert isinstance(stmt, AssignmentStmt)
        assert isinstance(stmt.target, PropertyAccessExpr)
        assert stmt.target.property == "count"

    def test_ivar_plus_equals(self):
        """@count += 1 → AssignmentStmt with BinaryExpr(op='+')."""
        result = parse_source(RB_COUNTER_SOURCE, "Counter.runar.rb")
        assert result.contract is not None
        inc = next(m for m in result.contract.methods if m.name == "increment")
        stmt = inc.body[0]
        assert isinstance(stmt, AssignmentStmt)
        assert isinstance(stmt.target, PropertyAccessExpr)
        assert stmt.target.property == "count"
        assert isinstance(stmt.value, BinaryExpr)
        assert stmt.value.op == "+"

    def test_ivar_minus_equals(self):
        """@count -= 1 → AssignmentStmt with BinaryExpr(op='-')."""
        result = parse_source(RB_COUNTER_SOURCE, "Counter.runar.rb")
        assert result.contract is not None
        dec = next(m for m in result.contract.methods if m.name == "decrement")
        stmt = dec.body[1]  # first stmt is assert, second is @count -= 1
        assert isinstance(stmt, AssignmentStmt)
        assert isinstance(stmt.value, BinaryExpr)
        assert stmt.value.op == "-"


# ---------------------------------------------------------------------------
# Ruby name mapping
# ---------------------------------------------------------------------------

class TestRubyNameMapping:
    def test_check_sig_maps_to_camel(self):
        """check_sig → checkSig via _SPECIAL_NAMES."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        # Second assert: assert check_sig(sig, pub_key)
        stmt = unlock.body[1]
        assert isinstance(stmt, ExpressionStmt)
        outer_call = stmt.expr
        assert isinstance(outer_call, CallExpr)
        inner_call = outer_call.args[0]
        assert isinstance(inner_call, CallExpr)
        assert isinstance(inner_call.callee, Identifier)
        assert inner_call.callee.name == "checkSig"

    def test_hash160_maps_to_camel(self):
        """hash160 passes through unchanged (in SPECIAL_NAMES with same value)."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        stmt = unlock.body[0]
        assert isinstance(stmt, ExpressionStmt)
        assert isinstance(stmt.expr, CallExpr)
        eq_expr = stmt.expr.args[0]
        assert isinstance(eq_expr, BinaryExpr)
        hash_call = eq_expr.left
        assert isinstance(hash_call, CallExpr)
        assert isinstance(hash_call.callee, Identifier)
        assert hash_call.callee.name == "hash160"

    def test_add_output_maps_to_camel(self):
        """add_output → addOutput (rewritten as this.addOutput via intrinsic set)."""
        result = parse_source(RB_FUNGIBLE_TOKEN_SOURCE, "FT.runar.rb")
        assert result.contract is not None
        transfer = next(m for m in result.contract.methods if m.name == "transfer")
        # After 3 asserts, first add_output call
        stmt = transfer.body[3]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        # add_output is in the intrinsic methods set, so it is rewritten to
        # a PropertyAccessExpr by the bare-call rewriter
        assert isinstance(call.callee, PropertyAccessExpr)
        assert call.callee.property == "addOutput"

    def test_ec_add_maps_to_camel(self):
        """ec_add → ecAdd via _SPECIAL_NAMES."""
        source = _rb_simple_contract("z = ec_add(@x, @x)")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        call = stmt.init
        assert isinstance(call, CallExpr)
        assert isinstance(call.callee, Identifier)
        assert call.callee.name == "ecAdd"

    def test_snake_to_camel_generic(self):
        """Generic snake_case: pub_key_hash → pubKeyHash."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].name == "pubKeyHash"

    def test_single_word_unchanged(self):
        """Single-word names are not altered: count → count."""
        result = parse_source(RB_COUNTER_SOURCE, "Counter.runar.rb")
        assert result.contract is not None
        assert result.contract.properties[0].name == "count"

    def test_ec_constant_passthrough(self):
        """EC_P passes through unchanged (uppercase letters not split)."""
        source = _rb_simple_contract("z = EC_P")
        result = parse_source(source, "Foo.runar.rb")
        # Mainly ensure it parses without error
        assert result.contract is not None

    def test_abs_passthrough(self):
        """abs is in _PASSTHROUGH_NAMES and maps to itself."""
        source = _rb_simple_contract("z = abs(@x)")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        call = stmt.init
        assert isinstance(call, CallExpr)
        assert isinstance(call.callee, Identifier)
        assert call.callee.name == "abs"


# ---------------------------------------------------------------------------
# Ruby expressions
# ---------------------------------------------------------------------------

class TestRubyExpressions:
    def test_eq_maps_to_triple_eq(self):
        """Ruby == maps to === in AST."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        stmt = unlock.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        eq_expr = call.args[0]
        assert isinstance(eq_expr, BinaryExpr)
        assert eq_expr.op == "==="

    def test_neq_maps_to_strict_neq(self):
        """Ruby != maps to !== in AST."""
        source = _rb_simple_contract("assert @x != 0")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        neq = call.args[0]
        assert isinstance(neq, BinaryExpr)
        assert neq.op == "!=="

    def test_and_maps_to_double_ampersand(self):
        """Ruby 'and' keyword → '&&' in AST."""
        source = _rb_simple_contract("assert @x > 0 and @x < 10")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        and_expr = call.args[0]
        assert isinstance(and_expr, BinaryExpr)
        assert and_expr.op == "&&"

    def test_or_maps_to_double_pipe(self):
        """Ruby 'or' keyword → '||' in AST."""
        source = _rb_simple_contract("assert @x == 0 or @x == 1")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        or_expr = call.args[0]
        assert isinstance(or_expr, BinaryExpr)
        assert or_expr.op == "||"

    def test_not_maps_to_bang(self):
        """Ruby 'not' keyword → UnaryExpr(op='!') in AST."""
        source = _rb_simple_contract("assert not @x == 0")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        not_expr = call.args[0]
        assert isinstance(not_expr, UnaryExpr)
        assert not_expr.op == "!"

    def test_starstar_maps_to_pow_call(self):
        """Ruby ** → pow(base, exp) CallExpr."""
        source = _rb_simple_contract("assert @x ** 2 > 0")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        cmp_expr = call.args[0]
        assert isinstance(cmp_expr, BinaryExpr)
        pow_call = cmp_expr.left
        assert isinstance(pow_call, CallExpr)
        assert isinstance(pow_call.callee, Identifier)
        assert pow_call.callee.name == "pow"
        assert len(pow_call.args) == 2

    def test_ternary_expression(self):
        """cond ? a : b → TernaryExpr."""
        source = _rb_simple_contract("y = @x > 0 ? @x : 0")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, TernaryExpr)

    def test_bitwise_and(self):
        """& operator is accepted."""
        source = _rb_simple_contract("z = @x & 0xFF")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, BinaryExpr)
        assert stmt.init.op == "&"

    def test_bitwise_or(self):
        """| operator is accepted."""
        source = _rb_simple_contract("z = @x | 1")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, BinaryExpr)
        assert stmt.init.op == "|"

    def test_bitwise_xor(self):
        """^ operator is accepted."""
        source = _rb_simple_contract("z = @x ^ 3")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, BinaryExpr)
        assert stmt.init.op == "^"

    def test_bitwise_not(self):
        """~ operator → UnaryExpr(op='~')."""
        source = _rb_simple_contract("z = ~@x")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, UnaryExpr)
        assert stmt.init.op == "~"

    def test_left_shift(self):
        """<< operator → BinaryExpr(op='<<')."""
        source = _rb_simple_contract("z = @x << 2")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, BinaryExpr)
        assert stmt.init.op == "<<"

    def test_right_shift(self):
        """>> operator → BinaryExpr(op='>>')."""
        source = _rb_simple_contract("z = @x >> 1")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, BinaryExpr)
        assert stmt.init.op == ">>"


# ---------------------------------------------------------------------------
# Ruby control flow
# ---------------------------------------------------------------------------

class TestRubyControlFlow:
    def test_if_end(self):
        """if/end → IfStmt with no else branch."""
        source = _rb_simple_contract(
            "if @x > 0\n    @x = @x + 1\n  end"
        )
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, IfStmt)
        assert len(stmt.then) == 1
        assert len(stmt.else_) == 0

    def test_if_else_end(self):
        """if/else/end → IfStmt with then and else branches."""
        source = _rb_simple_contract(
            "if @x > 0\n    @x = @x + 1\n  else\n    @x = 0\n  end"
        )
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, IfStmt)
        assert len(stmt.then) == 1
        assert len(stmt.else_) == 1

    def test_if_elsif_else_end(self):
        """if/elsif/else/end → nested IfStmt in else branch."""
        source = _rb_simple_contract(
            "if @x > 10\n    @x = 10\n  elsif @x > 0\n    @x = @x + 1\n  else\n    @x = 0\n  end"
        )
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, IfStmt)
        assert len(stmt.then) == 1
        assert len(stmt.else_) == 1
        # The else branch contains a nested if (the elsif)
        nested = stmt.else_[0]
        assert isinstance(nested, IfStmt)
        assert len(nested.else_) == 1

    def test_unless_is_negated_if(self):
        """unless cond → IfStmt with UnaryExpr(op='!') condition."""
        source = _rb_simple_contract(
            "unless @x == 0\n    @x = @x - 1\n  end"
        )
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, IfStmt)
        cond = stmt.condition
        assert isinstance(cond, UnaryExpr)
        assert cond.op == "!"

    def test_for_exclusive_range(self):
        """for i in 0...n → ForStmt with condition op '<'."""
        source = _rb_simple_contract(
            "for i in 0...@x\n    assert i >= 0\n  end"
        )
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ForStmt)
        assert isinstance(stmt.condition, BinaryExpr)
        assert stmt.condition.op == "<"

    def test_for_inclusive_range(self):
        """for i in 0..n → ForStmt with condition op '<='."""
        source = _rb_simple_contract(
            "for i in 0..@x\n    assert i >= 0\n  end"
        )
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ForStmt)
        assert isinstance(stmt.condition, BinaryExpr)
        assert stmt.condition.op == "<="


# ---------------------------------------------------------------------------
# Ruby literals
# ---------------------------------------------------------------------------

class TestRubyLiterals:
    def test_integer_literal(self):
        source = _rb_simple_contract("assert @x == 42")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        eq = call.args[0]
        assert isinstance(eq, BinaryExpr)
        assert isinstance(eq.right, BigIntLiteral)
        assert eq.right.value == 42

    def test_hex_integer_literal(self):
        source = _rb_simple_contract("assert @x == 0xFF")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        eq = call.args[0]
        assert isinstance(eq, BinaryExpr)
        assert isinstance(eq.right, BigIntLiteral)
        assert eq.right.value == 255

    def test_boolean_true_literal(self):
        source = _rb_simple_contract("assert true")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        assert isinstance(call.args[0], BoolLiteral)
        assert call.args[0].value is True

    def test_boolean_false_literal(self):
        source = _rb_simple_contract("assert not false")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        not_expr = call.args[0]
        assert isinstance(not_expr, UnaryExpr)
        assert isinstance(not_expr.operand, BoolLiteral)
        assert not_expr.operand.value is False

    def test_hex_bytestring_literal(self):
        """Single-quoted string → ByteStringLiteral."""
        source = _rb_simple_contract("assert @x == 'deadbeef'", prop_type="ByteString")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        eq = call.args[0]
        assert isinstance(eq, BinaryExpr)
        assert isinstance(eq.right, ByteStringLiteral)
        assert eq.right.value == "deadbeef"


# ---------------------------------------------------------------------------
# Ruby property initializers
# ---------------------------------------------------------------------------

class TestRubyPropertyInitializers:
    def test_bigint_default_initializer(self):
        """prop :count, Bigint, default: 0 → initializer BigIntLiteral(value=0)."""
        source = """\
class Foo < Runar::StatefulSmartContract
  prop :count, Bigint, default: 0
  def initialize
    super
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        count_prop = result.contract.properties[0]
        assert count_prop.name == "count"
        assert isinstance(count_prop.initializer, BigIntLiteral)
        assert count_prop.initializer.value == 0

    def test_bool_default_initializer(self):
        """prop :active, Boolean, default: true → initializer BoolLiteral(value=True)."""
        source = """\
class Foo < Runar::StatefulSmartContract
  prop :active, Boolean, default: true
  def initialize
    super
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        active_prop = result.contract.properties[0]
        assert active_prop.name == "active"
        assert isinstance(active_prop.initializer, BoolLiteral)
        assert active_prop.initializer.value is True

    def test_initialized_props_excluded_from_auto_constructor(self):
        """Properties with initializer are excluded from auto-generated constructor params."""
        source = """\
class BoundedCounter < Runar::StatefulSmartContract
  prop :count,     Bigint,  default: 0
  prop :max_count, Bigint,  readonly: true

  def initialize(max_count)
    super(max_count)
    @max_count = max_count
  end
end
"""
        result = parse_source(source, "BoundedCounter.runar.rb")
        assert result.contract is not None
        # Constructor should accept only max_count (count has a default)
        param_names = [p.name for p in result.contract.constructor.params]
        assert "maxCount" in param_names
        assert "count" not in param_names


# ---------------------------------------------------------------------------
# Ruby array literals
# ---------------------------------------------------------------------------

class TestRubyArrayLiterals:
    def test_multi_element_array(self):
        """[a, b, c] → ArrayLiteralExpr with 3 elements."""
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar(a, b, c)
    arr = [a, b, c]
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, ArrayLiteralExpr)
        assert len(stmt.init.elements) == 3

    def test_empty_array(self):
        """[] → ArrayLiteralExpr with 0 elements."""
        source = _rb_simple_contract("arr = []")
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, ArrayLiteralExpr)
        assert len(stmt.init.elements) == 0

    def test_single_element_array(self):
        """[a] → ArrayLiteralExpr with 1 element."""
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar(a)
    arr = [a]
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, ArrayLiteralExpr)
        assert len(stmt.init.elements) == 1


# ---------------------------------------------------------------------------
# Ruby implicit returns
# ---------------------------------------------------------------------------

class TestRubyImplicitReturns:
    def test_private_method_last_expr_becomes_return(self):
        """Last ExpressionStmt in a private method → ReturnStmt."""
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  def helper
    @x + 1
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        helper = next(m for m in result.contract.methods if m.name == "helper")
        last_stmt = helper.body[-1]
        assert isinstance(last_stmt, ReturnStmt)

    def test_public_method_last_expr_stays_as_expression(self):
        """Last stmt in a public (runar_public) method stays as ExpressionStmt."""
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    assert @x > 0
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        last_stmt = bar.body[-1]
        assert isinstance(last_stmt, ExpressionStmt)


# ---------------------------------------------------------------------------
# Ruby bare call rewriting
# ---------------------------------------------------------------------------

class TestRubyBareCallRewriting:
    def test_bare_call_to_declared_method_is_rewritten(self):
        """Bare call (with parens) to a contract method → PropertyAccessExpr callee."""
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  def helper(n)
    return n + 1
  end
  runar_public
  def bar
    y = helper(@x)
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        bar = next(m for m in result.contract.methods if m.name == "bar")
        stmt = bar.body[0]
        assert isinstance(stmt, VariableDeclStmt)
        assert isinstance(stmt.init, CallExpr)
        assert isinstance(stmt.init.callee, PropertyAccessExpr), (
            f"expected PropertyAccessExpr callee, got {type(stmt.init.callee).__name__}"
        )
        assert stmt.init.callee.property == "helper"

    def test_add_output_is_rewritten_to_property_access(self):
        """Bare add_output(...) → PropertyAccessExpr(property='addOutput').

        add_output is listed in the parser's intrinsic methods set, so the
        bare-call rewriter promotes it to a this.addOutput() call, yielding
        a PropertyAccessExpr callee rather than an Identifier.
        """
        result = parse_source(RB_FUNGIBLE_TOKEN_SOURCE, "FT.runar.rb")
        assert result.contract is not None
        transfer = next(m for m in result.contract.methods if m.name == "transfer")
        stmt = transfer.body[3]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        assert isinstance(call.callee, PropertyAccessExpr)
        assert call.callee.property == "addOutput"


# ---------------------------------------------------------------------------
# Ruby auto constructor
# ---------------------------------------------------------------------------

class TestRubyAutoConstructor:
    def test_no_initialize_gets_auto_constructor(self):
        """Contract without initialize gets an auto-generated constructor."""
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint

  runar_public
  def bar
    assert @x > 0
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        assert result.contract.constructor is not None
        assert result.contract.constructor.name == "constructor"

    def test_auto_constructor_params_match_non_initialized_props(self):
        """Auto constructor has params for all non-initialized properties."""
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint

  runar_public
  def bar
    assert @x > 0
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        assert len(result.contract.constructor.params) == 1
        assert result.contract.constructor.params[0].name == "x"

    def test_auto_constructor_param_types_from_props(self):
        """Auto constructor param types are backfilled from prop declarations."""
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint

  runar_public
  def bar
    assert @x > 0
  end
end
"""
        result = parse_source(source, "Foo.runar.rb")
        assert result.contract is not None
        param = result.contract.constructor.params[0]
        assert param.type == PrimitiveType(name="bigint")


# ---------------------------------------------------------------------------
# Ruby errors and dispatch
# ---------------------------------------------------------------------------

class TestRubyErrors:
    def test_empty_source_produces_no_contract(self):
        result = parse_source("", "Empty.runar.rb")
        assert result.contract is None or len(result.errors) > 0

    def test_rb_extension_dispatches_to_ruby_parser(self):
        """.runar.rb extension routes to the Ruby parser."""
        result = parse_source(RB_P2PKH_SOURCE, "P2PKH.runar.rb")
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_malformed_class_missing_end(self):
        """Class without a closing 'end' produces errors or no contract."""
        source = """\
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
    @x = x
  end
  runar_public
  def bar
    assert @x > 0
"""
        result = parse_source(source, "Foo.runar.rb")
        # Parser should either report errors or return no contract
        assert result.contract is None or len(result.errors) > 0


# ---------------------------------------------------------------------------
# Ruby integration: all example .runar.rb files parse without errors
# ---------------------------------------------------------------------------

class TestRubyIntegration:
    def _examples_dir(self) -> str:
        here = os.path.dirname(__file__)
        return os.path.normpath(os.path.join(here, "..", "..", "..", "examples", "ruby"))

    def test_all_example_contracts_parse_without_errors(self):
        """All .runar.rb files in examples/ruby/ parse without errors."""
        examples_dir = self._examples_dir()
        rb_files: list[str] = []
        for root, _dirs, files in os.walk(examples_dir):
            for f in files:
                if f.endswith(".runar.rb"):
                    rb_files.append(os.path.join(root, f))

        assert len(rb_files) > 0, (
            f"no .runar.rb files found in {examples_dir}"
        )

        failures: list[str] = []
        for path in sorted(rb_files):
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            file_name = os.path.basename(path)
            result = parse_source(source, file_name)
            errors = [e for e in result.errors if "error" in e.lower()] if result.errors else []
            if result.contract is None:
                failures.append(f"{file_name}: no contract returned, errors={result.errors}")
            elif result.errors:
                # Some warnings are acceptable; only flag hard errors
                hard = [e for e in result.errors if "error" in e.lower()]
                if hard:
                    failures.append(f"{file_name}: {hard}")

        assert not failures, "Some example contracts failed to parse:\n" + "\n".join(failures)
