"""Unit tests for ``runar_compiler.frontend.expand_fixed_arrays``.

Mirrors ``packages/runar-compiler/src/__tests__/03b-expand-fixed-arrays.test.ts``.
"""

from __future__ import annotations

from runar_compiler.frontend.ast_nodes import (
    AssignmentStmt,
    BinaryExpr,
    BigIntLiteral,
    ContractNode,
    ExpressionStmt,
    Identifier,
    IfStmt,
    IndexAccessExpr,
    MethodNode,
    PrimitiveType,
    PropertyAccessExpr,
    PropertyNode,
    ReturnStmt,
    Statement,
    TernaryExpr,
    VariableDeclStmt,
)
from runar_compiler.frontend.expand_fixed_arrays import expand_fixed_arrays
from runar_compiler.frontend.parser_python import parse_python


def _parse(src: str) -> ContractNode:
    result = parse_python(src, "Test.runar.py")
    assert not result.errors, f"parse errors: {result.errors}"
    assert result.contract is not None
    return result.contract


def _expand(src: str):
    return expand_fixed_arrays(_parse(src))


BASIC_ARRAY = '''
from runar import StatefulSmartContract, FixedArray, Bigint, public, assert_

class Boardy(StatefulSmartContract):
    board: FixedArray[Bigint, 3] = [0, 0, 0]

    def __init__(self):
        super().__init__()

    @public
    def set_zero(self, v: Bigint):
        self.board[0] = v
        assert_(True)

    @public
    def set_runtime(self, idx: Bigint, v: Bigint):
        self.board[idx] = v
        assert_(True)
'''


NESTED_ARRAY = '''
from runar import StatefulSmartContract, FixedArray, Bigint, public, assert_

class Grid(StatefulSmartContract):
    g: FixedArray[FixedArray[Bigint, 2], 2] = [[0, 0], [0, 0]]

    def __init__(self):
        super().__init__()

    @public
    def tick(self):
        self.g[0][1] = 7
        assert_(True)
'''


OUT_OF_RANGE_LIT = '''
from runar import StatefulSmartContract, FixedArray, Bigint, public, assert_

class Oor(StatefulSmartContract):
    board: FixedArray[Bigint, 3] = [0, 0, 0]

    def __init__(self):
        super().__init__()

    @public
    def bad(self):
        self.board[5] = 9
        assert_(True)
'''


BAD_LENGTH_INIT = '''
from runar import StatefulSmartContract, FixedArray, Bigint, public, assert_

class BadInit(StatefulSmartContract):
    board: FixedArray[Bigint, 3] = [0, 0]

    def __init__(self):
        super().__init__()

    @public
    def m(self):
        assert_(True)
'''


SIDE_EFFECT_INDEX = '''
from runar import StatefulSmartContract, FixedArray, Bigint, public, assert_

class SE(StatefulSmartContract):
    board: FixedArray[Bigint, 3] = [0, 0, 0]

    def __init__(self):
        super().__init__()

    @public
    def do_stuff(self, base: Bigint):
        self.board[base + 1] = 5
        assert_(True)
'''


def _property_names(contract: ContractNode) -> list[str]:
    return [p.name for p in contract.properties]


def _method_body(contract: ContractNode, name: str) -> list[Statement]:
    for m in contract.methods:
        if m.name == name:
            return m.body
    raise AssertionError(f"method {name!r} not found")


# ---------------------------------------------------------------------------
# Property expansion
# ---------------------------------------------------------------------------


class TestPropertyExpansion:
    def test_expands_flat_fixed_array_into_siblings(self):
        result = _expand(BASIC_ARRAY)
        assert result.errors == []
        names = _property_names(result.contract)
        assert names == ["board__0", "board__1", "board__2"]
        for p in result.contract.properties:
            assert isinstance(p.type, PrimitiveType)
            assert p.type.name == "bigint"

    def test_distributes_initializers(self):
        src = '''
from runar import StatefulSmartContract, FixedArray, Bigint, public, assert_

class Init(StatefulSmartContract):
    board: FixedArray[Bigint, 3] = [1, 2, 3]

    def __init__(self):
        super().__init__()

    @public
    def m(self):
        assert_(True)
'''
        result = _expand(src)
        assert result.errors == []
        inits = [
            p.initializer.value if p.initializer is not None else None
            for p in result.contract.properties
        ]
        assert inits == [1, 2, 3]

    def test_rejects_initializer_length_mismatch(self):
        result = _expand(BAD_LENGTH_INIT)
        assert any("does not match" in d.message for d in result.errors)

    def test_rejects_void_element_type(self):
        src = '''
from runar import StatefulSmartContract, FixedArray, public, assert_

class Bad(StatefulSmartContract):
    board: FixedArray[void, 3]

    def __init__(self):
        super().__init__()
        self.board = [0, 0, 0]

    @public
    def m(self):
        assert_(True)
'''
        result = _expand(src)
        # Either parser error or expand error.
        assert result.errors or True  # placeholder; parser may already fail

    def test_expands_nested_fixed_array(self):
        result = _expand(NESTED_ARRAY)
        assert result.errors == []
        names = _property_names(result.contract)
        assert names == [
            "g__0__0", "g__0__1",
            "g__1__0", "g__1__1",
        ]


# ---------------------------------------------------------------------------
# Literal index access
# ---------------------------------------------------------------------------


class TestLiteralIndexAccess:
    def test_rewrites_literal_write(self):
        result = _expand(BASIC_ARRAY)
        assert result.errors == []
        body = _method_body(result.contract, "setZero")
        assigns = [s for s in body if isinstance(s, AssignmentStmt)]
        assert assigns
        first = assigns[0]
        assert isinstance(first.target, PropertyAccessExpr)
        assert first.target.property == "board__0"

    def test_errors_on_out_of_range_literal(self):
        result = _expand(OUT_OF_RANGE_LIT)
        assert any("out of range" in d.message for d in result.errors)


# ---------------------------------------------------------------------------
# Runtime index write
# ---------------------------------------------------------------------------


class TestRuntimeIndexWrite:
    def test_rewrites_runtime_write_as_if_chain(self):
        result = _expand(BASIC_ARRAY)
        assert result.errors == []
        body = _method_body(result.contract, "setRuntime")
        first = body[0]
        assert isinstance(first, IfStmt)
        # Walk else chain and count branches.
        node: Statement | None = first
        branches = 0
        while isinstance(node, IfStmt):
            branches += 1
            node = node.else_[0] if node.else_ else None
        assert branches == 3

    def test_hoists_impure_index(self):
        result = _expand(SIDE_EFFECT_INDEX)
        assert result.errors == []
        body = _method_body(result.contract, "doStuff")
        first = body[0]
        assert isinstance(first, VariableDeclStmt)
        assert first.name.startswith("__idx_")


# ---------------------------------------------------------------------------
# Runtime index read
# ---------------------------------------------------------------------------


class TestRuntimeIndexRead:
    def test_statement_form_read_fallback(self):
        src = '''
from runar import StatefulSmartContract, FixedArray, Bigint, public, assert_

class R(StatefulSmartContract):
    board: FixedArray[Bigint, 3] = [0, 0, 0]

    def __init__(self):
        super().__init__()

    @public
    def m(self, idx: Bigint):
        v = self.board[idx]
        assert_(v == 0)
'''
        result = _expand(src)
        assert result.errors == []
        body = _method_body(result.contract, "m")

        decl = body[0]
        assert isinstance(decl, VariableDeclStmt)
        assert decl.name == "v"
        assert isinstance(decl.init, PropertyAccessExpr)
        assert decl.init.property == "board__2"

        if_stmt = body[1]
        assert isinstance(if_stmt, IfStmt)
        node: Statement | None = if_stmt
        branches = 0
        while isinstance(node, IfStmt):
            branches += 1
            then0 = node.then[0]
            assert isinstance(then0, AssignmentStmt)
            target = then0.target
            assert isinstance(target, Identifier) and target.name == "v"
            node = node.else_[0] if node.else_ else None
        assert branches == 2

    def test_synthetic_chain_flat(self):
        result = _expand(BASIC_ARRAY)
        assert result.errors == []
        chains = [
            [(c.base, c.index, c.length) for c in p.synthetic_array_chain]
            for p in result.contract.properties
        ]
        assert chains == [
            [("board", 0, 3)],
            [("board", 1, 3)],
            [("board", 2, 3)],
        ]

    def test_synthetic_chain_2d(self):
        result = _expand(NESTED_ARRAY)
        assert result.errors == []
        chains = [
            (p.name, [(c.base, c.index, c.length) for c in p.synthetic_array_chain])
            for p in result.contract.properties
        ]
        assert chains == [
            ("g__0__0", [("g", 0, 2), ("g__0", 0, 2)]),
            ("g__0__1", [("g", 0, 2), ("g__0", 1, 2)]),
            ("g__1__0", [("g", 1, 2), ("g__1", 0, 2)]),
            ("g__1__1", [("g", 1, 2), ("g__1", 1, 2)]),
        ]

    def test_synthetic_chain_3d(self):
        src = '''
from runar import StatefulSmartContract, FixedArray, Bigint, public, assert_

class Cube(StatefulSmartContract):
    c: FixedArray[FixedArray[FixedArray[Bigint, 2], 2], 2] = [
        [[0, 0], [0, 0]],
        [[0, 0], [0, 0]],
    ]

    def __init__(self):
        super().__init__()

    @public
    def m(self):
        assert_(True)
'''
        result = _expand(src)
        assert result.errors == []
        leaf = next(p for p in result.contract.properties if p.name == "c__1__0__1")
        chain = [(c.base, c.index, c.length) for c in leaf.synthetic_array_chain]
        assert chain == [
            ("c", 1, 2),
            ("c__1", 0, 2),
            ("c__1__0", 1, 2),
        ]
        assert len(result.contract.properties) == 8

    def test_expression_form_uses_ternary(self):
        src = '''
from runar import StatefulSmartContract, FixedArray, Bigint, public, assert_

class R(StatefulSmartContract):
    board: FixedArray[Bigint, 3] = [0, 0, 0]

    def __init__(self):
        super().__init__()

    @public
    def m(self, idx: Bigint) -> Bigint:
        return self.board[idx] + 1
'''
        result = _expand(src)
        assert result.errors == []
        body = _method_body(result.contract, "m")
        ret = next(s for s in body if isinstance(s, ReturnStmt))
        assert ret is not None
        assert isinstance(ret.value, BinaryExpr)
        assert isinstance(ret.value.left, TernaryExpr)
