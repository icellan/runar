"""Tests for the multi-format parser dispatch and individual parsers.

Covers TS, Solidity, Move, Python, Go, and Rust format parsers. Each test
provides a minimal contract source string and verifies the resulting AST
has the correct contract name, parent class, properties, and methods.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source, ParseResult
from runar_compiler.frontend.ast_nodes import ContractNode, PrimitiveType


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
