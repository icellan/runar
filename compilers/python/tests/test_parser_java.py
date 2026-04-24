"""Tests for the .runar.java parser (Python port of the authoritative Java
JavaParser surface spec).

Each test sanity-checks a specific slice of the Java subset that the
parser must accept or reject — paralleling the Java reference's JUnit
tests and the other format-parity tests in this directory.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.ast_nodes import (
    AssignmentStmt,
    BigIntLiteral,
    BinaryExpr,
    BoolLiteral,
    ByteStringLiteral,
    CallExpr,
    CustomType,
    ExpressionStmt,
    FixedArrayType,
    ForStmt,
    Identifier,
    IfStmt,
    IndexAccessExpr,
    MemberExpr,
    PrimitiveType,
    PropertyAccessExpr,
    ReturnStmt,
    TernaryExpr,
    UnaryExpr,
    VariableDeclStmt,
)


# ---------------------------------------------------------------------------
# P2PKH — the reference stateless contract used everywhere.
# ---------------------------------------------------------------------------

P2PKH_SOURCE = """
package runar.examples.p2pkh;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.hash160;

class P2PKH extends SmartContract {
    @Readonly Addr pubKeyHash;

    P2PKH(Addr pubKeyHash) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    @Public
    void unlock(Sig sig, PubKey pubKey) {
        assertThat(hash160(pubKey).equals(pubKeyHash));
        assertThat(checkSig(sig, pubKey));
    }
}
"""


class TestJavaP2PKH:
    def test_parses_to_expected_contract_shape(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.java")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "P2PKH"
        assert c.parent_class == "SmartContract"
        assert c.source_file == "P2PKH.runar.java"

        assert len(c.properties) == 1
        pkh = c.properties[0]
        assert pkh.name == "pubKeyHash"
        assert pkh.readonly is True
        assert pkh.type == PrimitiveType(name="Addr")
        assert pkh.initializer is None

    def test_constructor_with_super_and_this_assignment(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.java")
        c = result.contract
        assert c is not None
        ctor = c.constructor
        assert ctor.name == "constructor"
        assert len(ctor.params) == 1
        assert ctor.params[0].name == "pubKeyHash"

        assert len(ctor.body) == 2
        super_stmt = ctor.body[0]
        assert isinstance(super_stmt, ExpressionStmt)
        super_call = super_stmt.expr
        assert isinstance(super_call, CallExpr)
        assert isinstance(super_call.callee, Identifier)
        assert super_call.callee.name == "super"
        assert len(super_call.args) == 1
        assert isinstance(super_call.args[0], Identifier)
        assert super_call.args[0].name == "pubKeyHash"

        assign = ctor.body[1]
        assert isinstance(assign, AssignmentStmt)
        assert isinstance(assign.target, PropertyAccessExpr)
        assert assign.target.property == "pubKeyHash"
        assert isinstance(assign.value, Identifier)
        assert assign.value.name == "pubKeyHash"

    def test_unlock_method_with_static_imported_calls(self):
        result = parse_source(P2PKH_SOURCE, "P2PKH.runar.java")
        c = result.contract
        assert c is not None
        assert len(c.methods) == 1
        unlock = c.methods[0]
        assert unlock.name == "unlock"
        assert unlock.visibility == "public"
        assert len(unlock.params) == 2
        assert unlock.params[0].type == PrimitiveType(name="Sig")
        assert unlock.params[1].type == PrimitiveType(name="PubKey")

        assert len(unlock.body) == 2

        first_stmt = unlock.body[0]
        assert isinstance(first_stmt, ExpressionStmt)
        first_call = first_stmt.expr
        assert isinstance(first_call, CallExpr)
        # assertThat(...) resolves as a free call — no receiver.
        assert isinstance(first_call.callee, Identifier)
        assert first_call.callee.name == "assertThat"
        assert len(first_call.args) == 1

        equals_call = first_call.args[0]
        assert isinstance(equals_call, CallExpr)
        equals_callee = equals_call.callee
        assert isinstance(equals_callee, MemberExpr)
        assert equals_callee.property == "equals"
        hash_call = equals_callee.object
        assert isinstance(hash_call, CallExpr)
        assert isinstance(hash_call.callee, Identifier)
        assert hash_call.callee.name == "hash160"


# ---------------------------------------------------------------------------
# Counter — stateful contract.
# ---------------------------------------------------------------------------

COUNTER_SOURCE = """
package runar.examples.counter;

import java.math.BigInteger;
import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;

import static runar.lang.Builtins.assertThat;

class Counter extends StatefulSmartContract {
    BigInteger count;

    Counter(BigInteger count) {
        super(count);
        this.count = count;
    }

    @Public
    void increment() {
        this.count = this.count + BigInteger.ONE;
    }

    @Public
    void decrement() {
        assertThat(this.count > BigInteger.ZERO);
        this.count = this.count - BigInteger.ONE;
    }
}
"""


class TestJavaCounter:
    def test_parses_stateful_contract(self):
        result = parse_source(COUNTER_SOURCE, "Counter.runar.java")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert c.name == "Counter"
        assert c.parent_class == "StatefulSmartContract"
        assert len(c.properties) == 1
        assert c.properties[0].name == "count"
        assert c.properties[0].type == PrimitiveType(name="bigint")
        assert c.properties[0].readonly is False

    def test_increment_assigns_via_property_access(self):
        result = parse_source(COUNTER_SOURCE, "Counter.runar.java")
        c = result.contract
        assert c is not None
        inc = [m for m in c.methods if m.name == "increment"][0]
        assert inc.visibility == "public"
        assert len(inc.body) == 1
        assign = inc.body[0]
        assert isinstance(assign, AssignmentStmt)
        assert isinstance(assign.target, PropertyAccessExpr)
        assert assign.target.property == "count"
        rhs = assign.value
        assert isinstance(rhs, BinaryExpr)
        assert rhs.op == "+"
        assert isinstance(rhs.left, PropertyAccessExpr)
        assert rhs.left.property == "count"
        # BigInteger.ONE → BigIntLiteral(1).
        assert isinstance(rhs.right, BigIntLiteral)
        assert rhs.right.value == 1


# ---------------------------------------------------------------------------
# Property initializer.
# ---------------------------------------------------------------------------


class TestPropertyInitializer:
    def test_bigint_zero_initializer(self):
        src = """
        import java.math.BigInteger;
        import runar.lang.StatefulSmartContract;
        import runar.lang.annotations.Readonly;
        import runar.lang.types.PubKey;

        class Counter extends StatefulSmartContract {
            BigInteger count = BigInteger.ZERO;
            @Readonly PubKey owner;
            Counter(PubKey owner) { super(owner); this.owner = owner; }
        }
        """
        result = parse_source(src, "Counter.runar.java")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        assert len(c.properties) == 2
        count = next(p for p in c.properties if p.name == "count")
        assert count.initializer is not None
        assert isinstance(count.initializer, BigIntLiteral)
        assert count.initializer.value == 0

        # Initialized properties should not appear in the synthesized
        # constructor parameter list. Only `owner` is passed.
        ctor = c.constructor
        assert len(ctor.params) == 1
        assert ctor.params[0].name == "owner"


# ---------------------------------------------------------------------------
# Rejection tests.
# ---------------------------------------------------------------------------


class TestJavaRejections:
    def test_rejects_unknown_base_class(self):
        src = "class Bad extends Frobulator { }"
        result = parse_source(src, "Bad.runar.java")
        assert result.contract is None
        assert len(result.errors) == 1
        assert "Frobulator" in result.errors[0].message

    def test_rejects_missing_extends_clause(self):
        src = """
        import runar.lang.annotations.Readonly;
        import runar.lang.types.Addr;
        class Bad { @Readonly Addr pkh; }
        """
        result = parse_source(src, "Bad.runar.java")
        assert result.contract is None
        assert len(result.errors) == 1
        assert "must extend" in result.errors[0].message

    def test_rejects_bare_string_literal(self):
        src = """
        import runar.lang.SmartContract;
        import runar.lang.annotations.Readonly;
        import runar.lang.types.ByteString;
        class C extends SmartContract {
            @Readonly ByteString magic = "deadbeef";
            C(ByteString magic) { super(magic); this.magic = magic; }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.contract is None
        assert len(result.errors) == 1
        assert "String" in result.errors[0].message

    def test_rejects_multiple_constructors(self):
        src = """
        import runar.lang.SmartContract;
        import runar.lang.annotations.Readonly;
        import runar.lang.types.Addr;
        class Bad extends SmartContract {
            @Readonly Addr a;
            Bad() { super(); }
            Bad(Addr a) { super(a); this.a = a; }
        }
        """
        result = parse_source(src, "Bad.runar.java")
        assert result.contract is None
        assert len(result.errors) == 1
        assert "more than one constructor" in result.errors[0].message


# ---------------------------------------------------------------------------
# Literal / call promotion cases.
# ---------------------------------------------------------------------------


class TestLiteralPromotion:
    def test_bytestring_from_hex_promotes_to_literal(self):
        src = """
        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.annotations.Readonly;
        import runar.lang.types.ByteString;
        import static runar.lang.Builtins.assertThat;

        class C extends SmartContract {
            @Readonly ByteString magic;
            @Public
            void check() {
                assertThat(magic.equals(ByteString.fromHex("deadbeef")));
            }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        check = c.methods[0]
        stmt = check.body[0]
        assert isinstance(stmt, ExpressionStmt)
        assert_call = stmt.expr
        assert isinstance(assert_call, CallExpr)
        equals_call = assert_call.args[0]
        assert isinstance(equals_call, CallExpr)
        arg = equals_call.args[0]
        assert isinstance(arg, ByteStringLiteral)
        assert arg.value == "deadbeef"

    def test_biginteger_value_of_promotes_to_literal(self):
        src = """
        import java.math.BigInteger;
        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import runar.lang.annotations.Readonly;
        import static runar.lang.Builtins.assertThat;

        class C extends SmartContract {
            @Readonly BigInteger threshold;
            @Public
            void check(BigInteger x) {
                assertThat(x == BigInteger.valueOf(7));
            }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        check = c.methods[0]
        stmt = check.body[0]
        assert isinstance(stmt, ExpressionStmt)
        assert_call = stmt.expr
        assert isinstance(assert_call, CallExpr)
        cmp = assert_call.args[0]
        assert isinstance(cmp, BinaryExpr)
        assert cmp.op == "==="
        assert isinstance(cmp.left, Identifier)
        assert cmp.left.name == "x"
        # RHS should be a BigIntLiteral(7), NOT a CallExpr for valueOf.
        assert isinstance(cmp.right, BigIntLiteral)
        assert cmp.right.value == 7

    def test_biginteger_zero_one_two_ten_constants(self):
        src = """
        import java.math.BigInteger;
        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import static runar.lang.Builtins.assertThat;

        class C extends SmartContract {
            @Public
            void check() {
                assertThat(BigInteger.ZERO == BigInteger.ONE);
                assertThat(BigInteger.TWO == BigInteger.TEN);
            }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()
        c = result.contract
        assert c is not None
        body = c.methods[0].body
        assert len(body) == 2
        # Every RHS / LHS should be a BigIntLiteral.
        for stmt in body:
            assert isinstance(stmt, ExpressionStmt)
            assert_call = stmt.expr
            assert isinstance(assert_call, CallExpr)
            cmp = assert_call.args[0]
            assert isinstance(cmp, BinaryExpr)
            assert isinstance(cmp.left, BigIntLiteral)
            assert isinstance(cmp.right, BigIntLiteral)
        assert body[0].expr.args[0].left.value == 0
        assert body[0].expr.args[0].right.value == 1
        assert body[1].expr.args[0].left.value == 2
        assert body[1].expr.args[0].right.value == 10

    def test_integer_literal_becomes_bigint(self):
        src = """
        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import static runar.lang.Builtins.assertThat;

        class C extends SmartContract {
            @Public
            void check() {
                assertThat(1 + 2 == 3);
            }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()
        body = result.contract.methods[0].body
        expr = body[0].expr.args[0]
        # (1 + 2) === 3
        assert isinstance(expr, BinaryExpr)
        assert expr.op == "==="
        sum_expr = expr.left
        assert isinstance(sum_expr, BinaryExpr)
        assert isinstance(sum_expr.left, BigIntLiteral)
        assert sum_expr.left.value == 1
        assert isinstance(sum_expr.right, BigIntLiteral)
        assert sum_expr.right.value == 2


# ---------------------------------------------------------------------------
# Binary / unary / control-flow coverage.
# ---------------------------------------------------------------------------


class TestBinaryOps:
    def test_arithmetic_comparison_and_logical(self):
        src = """
        import java.math.BigInteger;
        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import static runar.lang.Builtins.assertThat;

        class C extends SmartContract {
            @Public
            void check(BigInteger a, BigInteger b, boolean c) {
                assertThat(a + b - 1 * 2 / 3 % 4 > 0 && c || !c);
            }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()

    def test_bitwise_and_shift_ops(self):
        src = """
        import java.math.BigInteger;
        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import static runar.lang.Builtins.assertThat;

        class C extends SmartContract {
            @Public
            void check(BigInteger a, BigInteger b) {
                assertThat(((a & b) | (a ^ b)) == (a << 1 >> 2));
                assertThat(~a != 0);
            }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()
        body = result.contract.methods[0].body
        assert len(body) == 2

    def test_ternary_and_index_access(self):
        src = """
        import java.math.BigInteger;
        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import static runar.lang.Builtins.assertThat;

        class C extends SmartContract {
            @Public
            void check(FixedArray<BigInteger, 4> arr, BigInteger i) {
                BigInteger x = arr[i] > 0 ? arr[i] : BigInteger.ZERO;
                assertThat(x > 0 || true);
            }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()
        body = result.contract.methods[0].body
        # First stmt is var decl.
        decl = body[0]
        assert isinstance(decl, VariableDeclStmt)
        assert decl.name == "x"
        assert isinstance(decl.init, TernaryExpr)

    def test_if_else_branches(self):
        src = """
        import java.math.BigInteger;
        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import static runar.lang.Builtins.assertThat;

        class C extends SmartContract {
            @Public
            void check(BigInteger x) {
                if (x > 0) {
                    assertThat(true);
                } else if (x == 0) {
                    assertThat(false);
                } else {
                    assertThat(x < 0);
                }
            }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()
        body = result.contract.methods[0].body
        assert isinstance(body[0], IfStmt)

    def test_for_loop_with_literal_bounds(self):
        src = """
        import java.math.BigInteger;
        import runar.lang.SmartContract;
        import runar.lang.annotations.Public;
        import static runar.lang.Builtins.assertThat;

        class C extends SmartContract {
            @Public
            void check() {
                for (int i = 0; i < 5; i = i + 1) {
                    assertThat(i >= 0);
                }
            }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()
        body = result.contract.methods[0].body
        assert isinstance(body[0], ForStmt)
        f = body[0]
        assert f.init is not None
        assert f.init.name == "i"
        assert isinstance(f.condition, BinaryExpr)
        assert isinstance(f.update, AssignmentStmt)


# ---------------------------------------------------------------------------
# Type mapping coverage.
# ---------------------------------------------------------------------------


class TestTypeMapping:
    def test_fixed_array_type(self):
        src = """
        import java.math.BigInteger;
        import runar.lang.SmartContract;
        import runar.lang.annotations.Readonly;

        class C extends SmartContract {
            @Readonly FixedArray<BigInteger, 8> arr;
            C(FixedArray<BigInteger, 8> arr) { super(arr); this.arr = arr; }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()
        c = result.contract
        prop = c.properties[0]
        assert isinstance(prop.type, FixedArrayType)
        assert prop.type.length == 8
        assert prop.type.element == PrimitiveType(name="bigint")

    def test_boolean_field_and_initializer(self):
        src = """
        import runar.lang.SmartContract;
        import runar.lang.annotations.Readonly;
        class C extends SmartContract {
            @Readonly boolean active = true;
            C() { super(); }
        }
        """
        result = parse_source(src, "C.runar.java")
        assert result.errors == [], result.error_strings()
        c = result.contract
        prop = c.properties[0]
        assert prop.type == PrimitiveType(name="boolean")
        assert isinstance(prop.initializer, BoolLiteral)
        assert prop.initializer.value is True
