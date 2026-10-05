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
        # assertThat(...) resolves as a free call — no receiver. The peer
        # parser rewrites the static-imported `assertThat` to `assert` so the
        # shared typechecker (which only knows `assert`) accepts the call.
        assert isinstance(first_call.callee, Identifier)
        assert first_call.callee.name == "assert"
        assert len(first_call.args) == 1

        # The native-Java `.equals(...)` value-equality method is lowered to
        # the canonical BinaryExpr(===, ...) so cross-format compilation
        # produces identical IR and script.
        equals_cmp = first_call.args[0]
        assert isinstance(equals_cmp, BinaryExpr)
        assert equals_cmp.op == "==="
        hash_call = equals_cmp.left
        assert isinstance(hash_call, CallExpr)
        assert isinstance(hash_call.callee, Identifier)
        assert hash_call.callee.name == "hash160"
        assert isinstance(equals_cmp.right, Identifier)
        assert equals_cmp.right.name == "pubKeyHash"


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
        # `.equals(...)` lowers to a canonical BinaryExpr(===, ...) with the
        # ByteStringLiteral (from fromHex) on the right.
        equals_cmp = assert_call.args[0]
        assert isinstance(equals_cmp, BinaryExpr)
        assert equals_cmp.op == "==="
        arg = equals_cmp.right
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


# ---------------------------------------------------------------------------
# N-023 (R49): a bare assignment to a property name is refused
# ---------------------------------------------------------------------------
#
# On the .runar.java surface a bare name that no local or parameter shadows IS
# the field, so `count = ...` writes state in Java. The parser used to lower it
# as a local rebind: a stateful contract compiled with no update_prop and its
# state never changed. Every tier refuses the bare form with the TS reference's
# diagnostic.
#
# Proves: the Python Java parser refuses each assignment spelling (=, op=,
# ++/--, statement or nested, any method incl. the constructor) on an
# unshadowed property, and accepts this.x writes plus local / parameter /
# for-variable shadowing, honouring Java block scope.
# Does not prove: other tiers (conformance/negatives N166 covers them), or
# anything about bare reads, which R49 leaves alone.

_BARE_MSG = "bare assignment to property 'count' is not allowed; write `this.count = ...`"
_BARE_CTOR = "super(count);\n        this.count = count;"


def _bare_counter(body: str, params: str = "", ctor_param: str = "count", ctor_body: str = _BARE_CTOR) -> str:
    return f"""
package p;
import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import static runar.lang.Builtins.assertThat;

class BareCounter extends StatefulSmartContract {{
    Bigint count;

    BareCounter(Bigint {ctor_param}) {{
        {ctor_body}
    }}

    @Public
    void increment({params}) {{
        {body}
    }}
}}
"""


def _bare_errors(src: str) -> list[str]:
    r = parse_source(src, "BareCounter.runar.java")
    return [e.message for e in r.errors if e.severity == "error"]


@pytest.mark.parametrize("body", [
    "count = count.plus(Bigint.ONE);",
    "count += Bigint.ONE;",
    "count++;",
    "--count;",
    "if (this.count.gt(Bigint.ZERO)) { count = Bigint.ONE; }",
    "for (Bigint i = Bigint.ZERO; i.lt(Bigint.TWO); count++) { assertThat(true); }",
    "assertThat((count++).gt(Bigint.ZERO));",
    "if (this.count.gt(Bigint.ZERO)) { Bigint count = Bigint.ONE; this.count = count; }\n        count = Bigint.TWO;",
    "count = Bigint.ONE;\n        Bigint count = Bigint.TWO;\n        this.count = count;",
], ids=["plain", "compound", "postfix-inc", "prefix-dec", "if-arm", "for-update", "nested",
        "after-if-scoped-local", "before-shadowing-local"])
def test_n023_refuses_bare_property_assignment(body: str) -> None:
    assert _BARE_MSG in _bare_errors(_bare_counter(body))


def test_n023_refuses_bare_property_assignment_in_constructor() -> None:
    src = _bare_counter("this.count = this.count.plus(Bigint.ONE);", ctor_param="c",
                        ctor_body="super(c);\n        count = c;")
    assert _BARE_MSG in _bare_errors(src)


@pytest.mark.parametrize("body,params", [
    ("this.count = this.count.plus(Bigint.ONE);", ""),
    ("Bigint count = this.count;\n        count = count.plus(Bigint.ONE);\n        this.count = count;", ""),
    ("count = count.plus(Bigint.ONE);\n        this.count = count;", "Bigint count"),
    ("for (Bigint count = Bigint.ZERO; count.lt(Bigint.TWO); count++) { assertThat(true); }\n"
     "        this.count = this.count.plus(Bigint.ONE);", ""),
    ("this.count = count.plus(Bigint.ONE);", ""),
], ids=["this-form", "local-shadow", "param-shadow", "for-var-shadow", "bare-read"])
def test_n023_accepts_shadowed_or_explicit_assignment(body: str, params: str) -> None:
    assert _bare_errors(_bare_counter(body, params)) == []


# ---------------------------------------------------------------------------
# N-134: TS's ten compound assignment operators (+ - * / % & | ^ << >>) lower
# `t op= e` to `t = t op e`, as a statement and in a for-header update slot
# (where the loop rule, not the parser, refuses a non-unit step). Before N-134
# Python refused `<<= >>= &= |= ^=` ("unexpected token '='") and `*= /= %=`
# in a for update. Proves the parsed shape for all ten on a local, a bigint
# property and a ByteString property, and in a for update. Does not prove
# byte parity with the other tiers (conformance/negatives/
# java-compound-assign-parity.test.ts pins that).
# ---------------------------------------------------------------------------

_N134_OPS = [("+=", "+"), ("-=", "-"), ("*=", "*"), ("/=", "/"), ("%=", "%"),
             ("<<=", "<<"), (">>=", ">>"), ("&=", "&"), ("|=", "|"), ("^=", "^")]


def _n134_name(e) -> str:
    if isinstance(e, Identifier):
        return e.name
    assert isinstance(e, PropertyAccessExpr), e
    return e.property


def _n134_assert_compound(stmt, target: str, op: str) -> None:
    assert isinstance(stmt, AssignmentStmt), stmt
    assert _n134_name(stmt.target) == target
    assert isinstance(stmt.value, BinaryExpr) and stmt.value.op == op, stmt.value
    assert _n134_name(stmt.value.left) == target


def test_n134_compound_assignment_all_ten_operators() -> None:
    lines = ["Bigint t = d;"]
    want = []
    for tok, op in _N134_OPS:
        lines += [f"t {tok} 3;", f"this.count {tok} t;"]
        want += [("t", op), ("count", op)]
    for tok, op in _N134_OPS[7:]:
        lines.append(f"this.tag {tok} m;")
        want.append(("tag", op))
    body = "\n        ".join(lines)
    src = f"""package p;
import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

class C extends StatefulSmartContract {{
    Bigint count;
    ByteString tag;

    C(Bigint count, ByteString tag) {{
        super(count, tag);
        this.count = count;
        this.tag = tag;
    }}

    @Public
    void step(Bigint d, ByteString m) {{
        {body}
    }}
}}
"""
    r = parse_source(src, "C.runar.java")
    assert [e.message for e in r.errors] == []
    stmts = r.contract.methods[0].body
    assert len(stmts) == len(want) + 1
    for stmt, (target, op) in zip(stmts[1:], want):
        _n134_assert_compound(stmt, target, op)


@pytest.mark.parametrize("tok,op", _N134_OPS, ids=[t for t, _ in _N134_OPS])
def test_n134_compound_assignment_in_for_update(tok: str, op: str) -> None:
    src = _bare_counter(f"for (Bigint i = Bigint.ZERO; i < 2; i {tok} 2) {{ assertThat(true); }}")
    r = parse_source(src, "BareCounter.runar.java")
    assert [e.message for e in r.errors] == []
    f = r.contract.methods[0].body[0]
    assert isinstance(f, ForStmt), f
    _n134_assert_compound(f.update, "i", op)
