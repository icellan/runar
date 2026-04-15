"""Tests for the Zig format parser (.runar.zig).

Covers basic contract parsing, properties, methods, operators, builtins,
while loops, if/else, compound assignments, and struct return syntax.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.parser_dispatch import parse_source, ParseResult
from runar_compiler.frontend.ast_nodes import (
    ContractNode,
    PrimitiveType,
    FixedArrayType,
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
    MemberExpr,
    IndexAccessExpr,
)


# ---------------------------------------------------------------------------
# Test source strings
# ---------------------------------------------------------------------------

ZIG_P2PKH_SOURCE = """\
const runar = @import("runar");

pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,

    pub fn init(pubKeyHash: runar.Addr) P2PKH {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.hash160(pubKey) == self.pubKeyHash);
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
"""

ZIG_COUNTER_SOURCE = """\
const runar = @import("runar");

pub const Counter = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) Counter {
        return .{ .count = count };
    }

    pub fn increment(self: *Counter) void {
        self.count += 1;
    }

    pub fn decrement(self: *Counter) void {
        runar.assert(self.count > 0);
        self.count -= 1;
    }
};
"""

ZIG_ESCROW_SOURCE = """\
const runar = @import("runar");

pub const Escrow = struct {
    pub const Contract = runar.SmartContract;

    buyer: runar.PubKey,
    seller: runar.PubKey,
    arbiter: runar.PubKey,

    pub fn init(buyer: runar.PubKey, seller: runar.PubKey, arbiter: runar.PubKey) Escrow {
        return .{
            .buyer = buyer,
            .seller = seller,
            .arbiter = arbiter,
        };
    }

    pub fn release(self: *const Escrow, sellerSig: runar.Sig, arbiterSig: runar.Sig) void {
        runar.assert(runar.checkSig(sellerSig, self.seller));
        runar.assert(runar.checkSig(arbiterSig, self.arbiter));
    }

    pub fn refund(self: *const Escrow, buyerSig: runar.Sig, arbiterSig: runar.Sig) void {
        runar.assert(runar.checkSig(buyerSig, self.buyer));
        runar.assert(runar.checkSig(arbiterSig, self.arbiter));
    }
};
"""

ZIG_ARITHMETIC_SOURCE = """\
const runar = @import("runar");

pub const Arithmetic = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) Arithmetic {
        return .{ .target = target };
    }

    pub fn verify(self: *const Arithmetic, a: i64, b: i64) void {
        const sum = a + b;
        const diff = a - b;
        const prod = a * b;
        const quot = @divTrunc(a, b);
        const result = sum + diff + prod + quot;
        runar.assert(result == self.target);
    }
};
"""

ZIG_BOUNDED_LOOP_SOURCE = """\
const runar = @import("runar");

pub const BoundedLoop = struct {
    pub const Contract = runar.SmartContract;

    expectedSum: i64,

    pub fn init(expectedSum: i64) BoundedLoop {
        return .{ .expectedSum = expectedSum };
    }

    pub fn verify(self: *const BoundedLoop, start: i64) void {
        var sum: i64 = 0;
        var i: i64 = 0;
        while (i < 5) : (i += 1) {
            sum = sum + start + i;
        }
        runar.assert(sum == self.expectedSum);
    }
};
"""

ZIG_IF_ELSE_SOURCE = """\
const runar = @import("runar");

pub const IfElse = struct {
    pub const Contract = runar.SmartContract;

    limit: i64,

    pub fn init(limit: i64) IfElse {
        return .{ .limit = limit };
    }

    pub fn check(self: *const IfElse, value: i64, mode: bool) void {
        var result: i64 = 0;
        if (mode) {
            result = value + self.limit;
        } else {
            result = value - self.limit;
        }
        runar.assert(result > 0);
    }
};
"""

ZIG_MULTI_METHOD_SOURCE = """\
const runar = @import("runar");

pub const MultiMethod = struct {
    pub const Contract = runar.SmartContract;

    owner: runar.PubKey,
    backup: runar.PubKey,

    pub fn init(owner: runar.PubKey, backup: runar.PubKey) MultiMethod {
        return .{ .owner = owner, .backup = backup };
    }

    fn computeThreshold(a: i64, b: i64) i64 {
        return a * b + 1;
    }

    pub fn spendWithOwner(self: *const MultiMethod, sig: runar.Sig, amount: i64) void {
        const threshold = computeThreshold(amount, 2);
        runar.assert(threshold > 10);
        runar.assert(runar.checkSig(sig, self.owner));
    }

    pub fn spendWithBackup(self: *const MultiMethod, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.backup));
    }
};
"""

ZIG_PROPERTY_INITIALIZERS_SOURCE = """\
const runar = @import("runar");

pub const PropertyInitializers = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,
    maxCount: i64,
    active: runar.Readonly(bool) = true,

    pub fn init(maxCount: i64) PropertyInitializers {
        return .{ .maxCount = maxCount };
    }

    pub fn increment(self: *PropertyInitializers, amount: i64) void {
        runar.assert(self.active);
        self.count = self.count + amount;
        runar.assert(self.count <= self.maxCount);
    }

    pub fn reset(self: *PropertyInitializers) void {
        self.count = 0;
    }
};
"""


# ---------------------------------------------------------------------------
# Basic contract parsing
# ---------------------------------------------------------------------------

class TestZigParserBasic:
    def test_parse_p2pkh_name(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_parse_p2pkh_parent_class(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        assert result.contract.parent_class == "SmartContract"

    def test_parse_p2pkh_has_constructor(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        assert result.contract.constructor is not None
        assert result.contract.constructor.name == "constructor"

    def test_parse_p2pkh_unlock_params(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        param_names = [p.name for p in unlock.params]
        assert "sig" in param_names
        assert "pubKey" in param_names

    def test_parse_p2pkh_property_readonly(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        prop = result.contract.properties[0]
        assert prop.name == "pubKeyHash"
        assert prop.readonly is True

    def test_parse_p2pkh_property_type(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        prop = result.contract.properties[0]
        assert prop.type == PrimitiveType(name="Addr")

    def test_parse_unsupported_extension(self):
        result = parse_source("something", "test.runar.xyz")
        assert len(result.errors) > 0

    def test_parse_source_file_set(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        assert result.contract.source_file == "P2PKH.runar.zig"


# ---------------------------------------------------------------------------
# Stateful contracts
# ---------------------------------------------------------------------------

class TestZigParserStateful:
    def test_stateful_counter_parent_class(self):
        result = parse_source(ZIG_COUNTER_SOURCE, "Counter.runar.zig")
        assert result.contract is not None
        assert result.contract.parent_class == "StatefulSmartContract"

    def test_stateful_counter_mutable_property(self):
        result = parse_source(ZIG_COUNTER_SOURCE, "Counter.runar.zig")
        assert result.contract is not None
        count_prop = result.contract.properties[0]
        assert count_prop.name == "count"
        assert count_prop.readonly is False

    def test_stateful_counter_strips_initializer_for_ctor_param(self):
        # `count: i64 = 0` collides with `pub fn init(count: i64)`: the ctor
        # param always overrides the default so the parser strips the
        # initializer to match the Zig compiler reference IR.
        result = parse_source(ZIG_COUNTER_SOURCE, "Counter.runar.zig")
        assert result.contract is not None
        count_prop = result.contract.properties[0]
        assert count_prop.initializer is None

    def test_stateful_no_arg_method(self):
        result = parse_source(ZIG_COUNTER_SOURCE, "Counter.runar.zig")
        assert result.contract is not None
        inc = next(m for m in result.contract.methods if m.name == "increment")
        assert len(inc.params) == 0

    def test_stateful_increment_has_compound_assignment(self):
        result = parse_source(ZIG_COUNTER_SOURCE, "Counter.runar.zig")
        assert result.contract is not None
        inc = next(m for m in result.contract.methods if m.name == "increment")
        # self.count += 1 → AssignmentStmt(target=PropertyAccess, value=BinaryExpr)
        assert len(inc.body) >= 1
        stmt = inc.body[0]
        assert isinstance(stmt, AssignmentStmt)
        assert isinstance(stmt.target, PropertyAccessExpr)
        assert stmt.target.property == "count"
        assert isinstance(stmt.value, BinaryExpr)
        assert stmt.value.op == "+"


# ---------------------------------------------------------------------------
# Multi-property contracts
# ---------------------------------------------------------------------------

class TestZigParserMultiProperty:
    def test_escrow_has_three_properties(self):
        result = parse_source(ZIG_ESCROW_SOURCE, "Escrow.runar.zig")
        assert result.contract is not None
        assert len(result.contract.properties) == 3

    def test_escrow_property_names(self):
        result = parse_source(ZIG_ESCROW_SOURCE, "Escrow.runar.zig")
        assert result.contract is not None
        names = [p.name for p in result.contract.properties]
        assert names == ["buyer", "seller", "arbiter"]

    def test_escrow_has_two_methods(self):
        result = parse_source(ZIG_ESCROW_SOURCE, "Escrow.runar.zig")
        assert result.contract is not None
        method_names = [m.name for m in result.contract.methods]
        assert "release" in method_names
        assert "refund" in method_names

    def test_escrow_all_properties_readonly(self):
        result = parse_source(ZIG_ESCROW_SOURCE, "Escrow.runar.zig")
        assert result.contract is not None
        for prop in result.contract.properties:
            assert prop.readonly is True

    def test_escrow_property_type(self):
        result = parse_source(ZIG_ESCROW_SOURCE, "Escrow.runar.zig")
        assert result.contract is not None
        for prop in result.contract.properties:
            assert prop.type == PrimitiveType(name="PubKey")


# ---------------------------------------------------------------------------
# Arithmetic and builtins
# ---------------------------------------------------------------------------

class TestZigParserArithmetic:
    def test_arithmetic_has_verify_method(self):
        result = parse_source(ZIG_ARITHMETIC_SOURCE, "Arithmetic.runar.zig")
        assert result.contract is not None
        method_names = [m.name for m in result.contract.methods]
        assert "verify" in method_names

    def test_arithmetic_verify_has_local_vars(self):
        result = parse_source(ZIG_ARITHMETIC_SOURCE, "Arithmetic.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        var_decls = [s for s in verify.body if isinstance(s, VariableDeclStmt)]
        # sum, diff, prod, quot, result
        assert len(var_decls) == 5

    def test_divtrunc_becomes_division(self):
        result = parse_source(ZIG_ARITHMETIC_SOURCE, "Arithmetic.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        # The quot variable should have init = BinaryExpr(op="/", ...)
        quot_decl = next(s for s in verify.body if isinstance(s, VariableDeclStmt) and s.name == "quot")
        assert isinstance(quot_decl.init, BinaryExpr)
        assert quot_decl.init.op == "/"

    def test_arithmetic_const_is_immutable(self):
        result = parse_source(ZIG_ARITHMETIC_SOURCE, "Arithmetic.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        sum_decl = next(s for s in verify.body if isinstance(s, VariableDeclStmt) and s.name == "sum")
        assert sum_decl.mutable is False


# ---------------------------------------------------------------------------
# While loops (bounded loops)
# ---------------------------------------------------------------------------

class TestZigParserWhileLoop:
    def test_while_loop_produces_for_stmt(self):
        result = parse_source(ZIG_BOUNDED_LOOP_SOURCE, "BoundedLoop.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        for_stmts = [s for s in verify.body if isinstance(s, ForStmt)]
        assert len(for_stmts) == 1

    def test_while_loop_init_is_merged(self):
        result = parse_source(ZIG_BOUNDED_LOOP_SOURCE, "BoundedLoop.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        for_stmt = next(s for s in verify.body if isinstance(s, ForStmt))
        # The init should be the `var i: i64 = 0` (merged from preceding decl)
        assert isinstance(for_stmt.init, VariableDeclStmt)
        assert for_stmt.init.name == "i"

    def test_while_loop_condition(self):
        result = parse_source(ZIG_BOUNDED_LOOP_SOURCE, "BoundedLoop.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        for_stmt = next(s for s in verify.body if isinstance(s, ForStmt))
        assert isinstance(for_stmt.condition, BinaryExpr)
        assert for_stmt.condition.op == "<"

    def test_while_loop_has_update(self):
        result = parse_source(ZIG_BOUNDED_LOOP_SOURCE, "BoundedLoop.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        for_stmt = next(s for s in verify.body if isinstance(s, ForStmt))
        # Update should be an assignment: i = i + 1
        assert isinstance(for_stmt.update, AssignmentStmt)


# ---------------------------------------------------------------------------
# If/else
# ---------------------------------------------------------------------------

class TestZigParserIfElse:
    def test_if_else_produces_if_stmt(self):
        result = parse_source(ZIG_IF_ELSE_SOURCE, "IfElse.runar.zig")
        assert result.contract is not None
        check = next(m for m in result.contract.methods if m.name == "check")
        if_stmts = [s for s in check.body if isinstance(s, IfStmt)]
        assert len(if_stmts) == 1

    def test_if_has_then_branch(self):
        result = parse_source(ZIG_IF_ELSE_SOURCE, "IfElse.runar.zig")
        assert result.contract is not None
        check = next(m for m in result.contract.methods if m.name == "check")
        if_stmt = next(s for s in check.body if isinstance(s, IfStmt))
        assert len(if_stmt.then) >= 1

    def test_if_has_else_branch(self):
        result = parse_source(ZIG_IF_ELSE_SOURCE, "IfElse.runar.zig")
        assert result.contract is not None
        check = next(m for m in result.contract.methods if m.name == "check")
        if_stmt = next(s for s in check.body if isinstance(s, IfStmt))
        assert len(if_stmt.else_) >= 1


# ---------------------------------------------------------------------------
# Multi-method and bare method call rewriting
# ---------------------------------------------------------------------------

class TestZigParserMultiMethod:
    def test_private_method_visibility(self):
        result = parse_source(ZIG_MULTI_METHOD_SOURCE, "MultiMethod.runar.zig")
        assert result.contract is not None
        compute = next(m for m in result.contract.methods if m.name == "computeThreshold")
        assert compute.visibility == "private"

    def test_public_method_visibility(self):
        result = parse_source(ZIG_MULTI_METHOD_SOURCE, "MultiMethod.runar.zig")
        assert result.contract is not None
        spend = next(m for m in result.contract.methods if m.name == "spendWithOwner")
        assert spend.visibility == "public"

    def test_bare_method_call_rewritten_to_this(self):
        """computeThreshold(amount, 2) should be rewritten as this.computeThreshold(...)."""
        result = parse_source(ZIG_MULTI_METHOD_SOURCE, "MultiMethod.runar.zig")
        assert result.contract is not None
        spend = next(m for m in result.contract.methods if m.name == "spendWithOwner")
        # First statement: const threshold = computeThreshold(amount, 2)
        # After rewriting, the callee should be PropertyAccessExpr
        threshold_decl = spend.body[0]
        assert isinstance(threshold_decl, VariableDeclStmt)
        assert isinstance(threshold_decl.init, CallExpr)
        assert isinstance(threshold_decl.init.callee, PropertyAccessExpr)
        assert threshold_decl.init.callee.property == "computeThreshold"

    def test_private_method_has_params(self):
        result = parse_source(ZIG_MULTI_METHOD_SOURCE, "MultiMethod.runar.zig")
        assert result.contract is not None
        compute = next(m for m in result.contract.methods if m.name == "computeThreshold")
        param_names = [p.name for p in compute.params]
        assert "a" in param_names
        assert "b" in param_names

    def test_private_method_has_return(self):
        result = parse_source(ZIG_MULTI_METHOD_SOURCE, "MultiMethod.runar.zig")
        assert result.contract is not None
        compute = next(m for m in result.contract.methods if m.name == "computeThreshold")
        return_stmts = [s for s in compute.body if isinstance(s, ReturnStmt)]
        assert len(return_stmts) == 1


# ---------------------------------------------------------------------------
# Property initializers and readonly
# ---------------------------------------------------------------------------

class TestZigParserPropertyInitializers:
    def test_initializer_count_zero(self):
        result = parse_source(ZIG_PROPERTY_INITIALIZERS_SOURCE, "PI.runar.zig")
        assert result.contract is not None
        count = next(p for p in result.contract.properties if p.name == "count")
        assert isinstance(count.initializer, BigIntLiteral)
        assert count.initializer.value == 0

    def test_initializer_active_true(self):
        result = parse_source(ZIG_PROPERTY_INITIALIZERS_SOURCE, "PI.runar.zig")
        assert result.contract is not None
        active = next(p for p in result.contract.properties if p.name == "active")
        assert isinstance(active.initializer, BoolLiteral)
        assert active.initializer.value is True

    def test_readonly_type_annotation(self):
        """runar.Readonly(bool) should make the property readonly."""
        result = parse_source(ZIG_PROPERTY_INITIALIZERS_SOURCE, "PI.runar.zig")
        assert result.contract is not None
        active = next(p for p in result.contract.properties if p.name == "active")
        assert active.readonly is True

    def test_non_readonly_mutable_property(self):
        result = parse_source(ZIG_PROPERTY_INITIALIZERS_SOURCE, "PI.runar.zig")
        assert result.contract is not None
        count = next(p for p in result.contract.properties if p.name == "count")
        assert count.readonly is False

    def test_constructor_params_exclude_initialized(self):
        """Properties with initializers should be excluded from the constructor."""
        result = parse_source(ZIG_PROPERTY_INITIALIZERS_SOURCE, "PI.runar.zig")
        assert result.contract is not None
        ctor = result.contract.constructor
        param_names = [p.name for p in ctor.params]
        assert "maxCount" in param_names
        # count and active have initializers, should not be constructor params
        assert "count" not in param_names
        assert "active" not in param_names


# ---------------------------------------------------------------------------
# Type mapping
# ---------------------------------------------------------------------------

class TestZigParserTypeMapping:
    def test_i64_maps_to_bigint(self):
        result = parse_source(ZIG_COUNTER_SOURCE, "Counter.runar.zig")
        assert result.contract is not None
        count = result.contract.properties[0]
        assert count.type == PrimitiveType(name="bigint")

    def test_runar_addr_maps_to_addr(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        prop = result.contract.properties[0]
        assert prop.type == PrimitiveType(name="Addr")

    def test_runar_pubkey_maps_to_pubkey(self):
        result = parse_source(ZIG_ESCROW_SOURCE, "Escrow.runar.zig")
        assert result.contract is not None
        prop = result.contract.properties[0]
        assert prop.type == PrimitiveType(name="PubKey")

    def test_bool_maps_to_boolean(self):
        result = parse_source(ZIG_IF_ELSE_SOURCE, "IfElse.runar.zig")
        assert result.contract is not None
        check = next(m for m in result.contract.methods if m.name == "check")
        mode_param = next(p for p in check.params if p.name == "mode")
        assert mode_param.type == PrimitiveType(name="boolean")


# ---------------------------------------------------------------------------
# Builtin stripping and expressions
# ---------------------------------------------------------------------------

class TestZigParserExpressions:
    def test_runar_assert_becomes_assert_call(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        # First statement: runar.assert(runar.hash160(pubKey) == self.pubKeyHash)
        stmt = unlock.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        assert isinstance(call.callee, Identifier)
        assert call.callee.name == "assert"

    def test_runar_hash160_becomes_hash160(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        stmt = unlock.body[0]
        assert isinstance(stmt, ExpressionStmt)
        outer_call = stmt.expr
        assert isinstance(outer_call, CallExpr)
        # Inner arg: hash160(pubKey) == self.pubKeyHash
        eq_expr = outer_call.args[0]
        assert isinstance(eq_expr, BinaryExpr)
        assert eq_expr.op == "==="
        assert isinstance(eq_expr.left, CallExpr)
        assert isinstance(eq_expr.left.callee, Identifier)
        assert eq_expr.left.callee.name == "hash160"

    def test_self_property_access(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        stmt = unlock.body[0]
        assert isinstance(stmt, ExpressionStmt)
        outer_call = stmt.expr
        assert isinstance(outer_call, CallExpr)
        eq_expr = outer_call.args[0]
        assert isinstance(eq_expr, BinaryExpr)
        assert isinstance(eq_expr.right, PropertyAccessExpr)
        assert eq_expr.right.property == "pubKeyHash"

    def test_equality_maps_to_triple_equals(self):
        """Zig == maps to AST === (same as TS reference)."""
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        unlock = next(m for m in result.contract.methods if m.name == "unlock")
        stmt = unlock.body[0]
        assert isinstance(stmt, ExpressionStmt)
        outer_call = stmt.expr
        assert isinstance(outer_call, CallExpr)
        eq_expr = outer_call.args[0]
        assert isinstance(eq_expr, BinaryExpr)
        assert eq_expr.op == "==="

    def test_greater_than_comparison(self):
        result = parse_source(ZIG_COUNTER_SOURCE, "Counter.runar.zig")
        assert result.contract is not None
        dec = next(m for m in result.contract.methods if m.name == "decrement")
        # First statement: runar.assert(self.count > 0)
        stmt = dec.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        cmp = call.args[0]
        assert isinstance(cmp, BinaryExpr)
        assert cmp.op == ">"


# ---------------------------------------------------------------------------
# Constructor handling
# ---------------------------------------------------------------------------

class TestZigParserConstructor:
    def test_constructor_has_super_call(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        ctor = result.contract.constructor
        # First statement should be super() call
        first = ctor.body[0]
        assert isinstance(first, ExpressionStmt)
        assert isinstance(first.expr, CallExpr)
        assert isinstance(first.expr.callee, Identifier)
        assert first.expr.callee.name == "super"

    def test_constructor_has_property_assignments(self):
        result = parse_source(ZIG_P2PKH_SOURCE, "P2PKH.runar.zig")
        assert result.contract is not None
        ctor = result.contract.constructor
        # Should have super() + property assignment(s)
        assignments = [s for s in ctor.body if isinstance(s, AssignmentStmt)]
        assert len(assignments) >= 1
        assert isinstance(assignments[0].target, PropertyAccessExpr)
        assert assignments[0].target.property == "pubKeyHash"

    def test_constructor_params_match_fields(self):
        result = parse_source(ZIG_ESCROW_SOURCE, "Escrow.runar.zig")
        assert result.contract is not None
        ctor = result.contract.constructor
        param_names = [p.name for p in ctor.params]
        assert param_names == ["buyer", "seller", "arbiter"]


# ---------------------------------------------------------------------------
# Hex literal and string handling
# ---------------------------------------------------------------------------

class TestZigParserLiterals:
    def test_string_literal_as_bytestring(self):
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    data: runar.ByteString,

    pub fn init(data: runar.ByteString) Test {
        return .{ .data = data };
    }

    pub fn verify(self: *const Test) void {
        runar.assert(self.data == "abcdef");
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        stmt = verify.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        eq_expr = call.args[0]
        assert isinstance(eq_expr, BinaryExpr)
        assert isinstance(eq_expr.right, ByteStringLiteral)
        assert eq_expr.right.value == "abcdef"

    def test_number_literal(self):
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    x: i64,

    pub fn init(x: i64) Test {
        return .{ .x = x };
    }

    pub fn verify(self: *const Test) void {
        runar.assert(self.x == 42);
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        stmt = verify.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        eq_expr = call.args[0]
        assert isinstance(eq_expr, BinaryExpr)
        assert isinstance(eq_expr.right, BigIntLiteral)
        assert eq_expr.right.value == 42

    def test_hex_number_literal(self):
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    x: i64,

    pub fn init(x: i64) Test {
        return .{ .x = x };
    }

    pub fn verify(self: *const Test) void {
        runar.assert(self.x == 0xFF);
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        stmt = verify.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        eq_expr = call.args[0]
        assert isinstance(eq_expr, BinaryExpr)
        assert isinstance(eq_expr.right, BigIntLiteral)
        assert eq_expr.right.value == 255


# ---------------------------------------------------------------------------
# Zig-specific builtins
# ---------------------------------------------------------------------------

class TestZigBuiltins:
    def test_mod_builtin(self):
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    x: i64,

    pub fn init(x: i64) Test {
        return .{ .x = x };
    }

    pub fn verify(self: *const Test, a: i64, b: i64) void {
        const rem = @mod(a, b);
        runar.assert(rem == self.x);
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        rem_decl = next(s for s in verify.body if isinstance(s, VariableDeclStmt) and s.name == "rem")
        assert isinstance(rem_decl.init, BinaryExpr)
        assert rem_decl.init.op == "%"

    def test_intcast_unwraps(self):
        """@intCast(expr) should just return the inner expr."""
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    x: i64,

    pub fn init(x: i64) Test {
        return .{ .x = x };
    }

    pub fn verify(self: *const Test, a: i64) void {
        const val = @intCast(a);
        runar.assert(val == self.x);
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        val_decl = next(s for s in verify.body if isinstance(s, VariableDeclStmt) and s.name == "val")
        # @intCast(a) should unwrap to just Identifier(name="a")
        assert isinstance(val_decl.init, Identifier)
        assert val_decl.init.name == "a"

    def test_shl_exact_builtin(self):
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    x: i64,

    pub fn init(x: i64) Test {
        return .{ .x = x };
    }

    pub fn verify(self: *const Test, a: i64) void {
        const shifted = @shlExact(a, 2);
        runar.assert(shifted == self.x);
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        shifted = next(s for s in verify.body if isinstance(s, VariableDeclStmt) and s.name == "shifted")
        assert isinstance(shifted.init, BinaryExpr)
        assert shifted.init.op == "<<"


# ---------------------------------------------------------------------------
# Array type and array literal
# ---------------------------------------------------------------------------

class TestZigParserArrays:
    def test_fixed_array_type(self):
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    data: [3]runar.ByteString,

    pub fn init(data: [3]runar.ByteString) Test {
        return .{ .data = data };
    }

    pub fn verify(self: *const Test) void {
        runar.assert(self.data[0] == "aa");
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        prop = result.contract.properties[0]
        assert isinstance(prop.type, FixedArrayType)
        assert prop.type.length == 3
        assert isinstance(prop.type.element, PrimitiveType)
        assert prop.type.element.name == "ByteString"

    def test_array_literal_dot_brace(self):
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    x: i64,

    pub fn init(x: i64) Test {
        return .{ .x = x };
    }

    pub fn verify(self: *const Test) void {
        const arr = .{ 1, 2, 3 };
        runar.assert(self.x == 1);
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        arr_decl = next(s for s in verify.body if isinstance(s, VariableDeclStmt) and s.name == "arr")
        assert isinstance(arr_decl.init, ArrayLiteralExpr)
        assert len(arr_decl.init.elements) == 3


# ---------------------------------------------------------------------------
# Unary operators
# ---------------------------------------------------------------------------

class TestZigParserUnary:
    def test_negation(self):
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    x: i64,

    pub fn init(x: i64) Test {
        return .{ .x = x };
    }

    pub fn verify(self: *const Test, a: i64) void {
        const neg = -a;
        runar.assert(neg == self.x);
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        neg_decl = next(s for s in verify.body if isinstance(s, VariableDeclStmt) and s.name == "neg")
        assert isinstance(neg_decl.init, UnaryExpr)
        assert neg_decl.init.op == "-"

    def test_logical_not(self):
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    x: i64,

    pub fn init(x: i64) Test {
        return .{ .x = x };
    }

    pub fn verify(self: *const Test, flag: bool) void {
        runar.assert(!flag);
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        stmt = verify.body[0]
        assert isinstance(stmt, ExpressionStmt)
        call = stmt.expr
        assert isinstance(call, CallExpr)
        assert isinstance(call.args[0], UnaryExpr)
        assert call.args[0].op == "!"

    def test_bitwise_not(self):
        source = """\
const runar = @import("runar");

pub const Test = struct {
    pub const Contract = runar.SmartContract;

    x: i64,

    pub fn init(x: i64) Test {
        return .{ .x = x };
    }

    pub fn verify(self: *const Test, a: i64) void {
        const inv = ~a;
        runar.assert(inv == self.x);
    }
};
"""
        result = parse_source(source, "Test.runar.zig")
        assert result.contract is not None
        verify = next(m for m in result.contract.methods if m.name == "verify")
        inv_decl = next(s for s in verify.body if isinstance(s, VariableDeclStmt) and s.name == "inv")
        assert isinstance(inv_decl.init, UnaryExpr)
        assert inv_decl.init.op == "~"


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

class TestZigParserComments:
    def test_line_comment_skipped(self):
        source = """\
const runar = @import("runar");

// This is a line comment
pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr, // inline comment

    pub fn init(pubKeyHash: runar.Addr) P2PKH {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
"""
        result = parse_source(source, "P2PKH.runar.zig")
        assert len(result.errors) == 0
        assert result.contract is not None
        assert result.contract.name == "P2PKH"

    def test_block_comment_skipped(self):
        source = """\
const runar = @import("runar");

/* Block comment */
pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,

    pub fn init(pubKeyHash: runar.Addr) P2PKH {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
"""
        result = parse_source(source, "P2PKH.runar.zig")
        assert len(result.errors) == 0
        assert result.contract is not None
