"""AST node types for the Runar compiler frontend.

This module defines all AST node types used by all Runar parsers. It is a
direct port of ``compilers/go/frontend/ast.go``.

Uses Python 3.10+ features: dataclasses, ``X | Y`` union syntax, and
``match/case`` readiness via the class hierarchy.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Source locations
# ---------------------------------------------------------------------------

@dataclass
class SourceLocation:
    """A position in a source file."""

    file: str = ""
    line: int = 0
    column: int = 0


# ---------------------------------------------------------------------------
# Type nodes
# ---------------------------------------------------------------------------

@dataclass
class PrimitiveType:
    """A built-in scalar type like bigint, boolean, ByteString, etc."""

    name: str  # e.g. "bigint", "boolean", "ByteString", "PubKey", ...


@dataclass
class FixedArrayType:
    """A fixed-length array type: ``FixedArray<T, N>``."""

    element: TypeNode
    length: int


@dataclass
class CustomType:
    """An unrecognized type reference."""

    name: str


# Discriminated union of all type nodes.
TypeNode = PrimitiveType | FixedArrayType | CustomType


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------

@dataclass
class BigIntLiteral:
    """A bigint literal like ``42n``."""

    value: int


@dataclass
class BoolLiteral:
    """A boolean literal."""

    value: bool


@dataclass
class ByteStringLiteral:
    """A hex-encoded byte string literal."""

    value: str  # hex-encoded


@dataclass
class Identifier:
    """A variable or name reference."""

    name: str


@dataclass
class PropertyAccessExpr:
    """``this.x`` -- property access on the contract."""

    property: str


@dataclass
class MemberExpr:
    """A member access like ``obj.property`` (not ``this.x``)."""

    object: Expression
    property: str


@dataclass
class BinaryExpr:
    """A binary operation like ``a + b``."""

    op: str  # "+", "-", "*", "/", "%", "===", "!==", "<", "<=", ">", ">=", "&&", "||", "&", "|", "^", "<<", ">>"
    left: Expression
    right: Expression


@dataclass
class UnaryExpr:
    """A unary operation like ``!a``, ``-a``, ``~a``."""

    op: str  # "!", "-", "~"
    operand: Expression


@dataclass
class CallExpr:
    """A function/method call."""

    callee: Expression
    args: list[Expression] = field(default_factory=list)


@dataclass
class TernaryExpr:
    """A conditional expression: ``cond ? a : b``."""

    condition: Expression
    consequent: Expression
    alternate: Expression


@dataclass
class IndexAccessExpr:
    """Array index access: ``arr[i]``."""

    object: Expression
    index: Expression


@dataclass
class IncrementExpr:
    """``i++`` or ``++i``."""

    operand: Expression
    prefix: bool = False


@dataclass
class DecrementExpr:
    """``i--`` or ``--i``."""

    operand: Expression
    prefix: bool = False


@dataclass
class ArrayLiteralExpr:
    """An array literal: ``[elem, ...]``."""

    elements: list[Expression] = field(default_factory=list)


# Discriminated union of all expression nodes.
Expression = (
    BigIntLiteral
    | BoolLiteral
    | ByteStringLiteral
    | Identifier
    | PropertyAccessExpr
    | MemberExpr
    | BinaryExpr
    | UnaryExpr
    | CallExpr
    | TernaryExpr
    | IndexAccessExpr
    | IncrementExpr
    | DecrementExpr
    | ArrayLiteralExpr
)


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------

@dataclass
class VariableDeclStmt:
    """``const x: T = expr`` or ``let x: T = expr``."""

    name: str
    type: TypeNode | None = None
    mutable: bool = False  # const = False, let = True
    init: Expression | None = None
    source_location: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class AssignmentStmt:
    """``target = value``."""

    target: Expression | None = None
    value: Expression | None = None
    source_location: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class IfStmt:
    """An ``if``/``else`` statement."""

    condition: Expression | None = None
    then: list[Statement] = field(default_factory=list)
    else_: list[Statement] = field(default_factory=list)
    source_location: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class ForStmt:
    """A ``for`` loop with constant bounds."""

    init: VariableDeclStmt | None = None
    condition: Expression | None = None
    update: Statement | None = None
    body: list[Statement] = field(default_factory=list)
    source_location: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class ReturnStmt:
    """A ``return`` statement."""

    value: Expression | None = None
    source_location: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class ExpressionStmt:
    """An expression used as a statement."""

    expr: Expression | None = None
    source_location: SourceLocation = field(default_factory=SourceLocation)


# Discriminated union of all statement nodes.
Statement = (
    VariableDeclStmt
    | AssignmentStmt
    | IfStmt
    | ForStmt
    | ReturnStmt
    | ExpressionStmt
)


# ---------------------------------------------------------------------------
# Top-level nodes
# ---------------------------------------------------------------------------

@dataclass
class ParamNode:
    """A method parameter."""

    name: str = ""
    type: TypeNode | None = None


@dataclass
class PropertyNode:
    """A contract property declaration."""

    name: str = ""
    type: TypeNode | None = None
    readonly: bool = False
    initializer: Expression | None = None
    source_location: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class MethodNode:
    """A contract method or constructor."""

    name: str = ""
    params: list[ParamNode] = field(default_factory=list)
    body: list[Statement] = field(default_factory=list)
    visibility: str = "public"  # "public" or "private"
    source_location: SourceLocation = field(default_factory=SourceLocation)


@dataclass
class ContractNode:
    """The parsed representation of a Runar smart contract class."""

    name: str = ""
    parent_class: str = ""  # "SmartContract" or "StatefulSmartContract"
    properties: list[PropertyNode] = field(default_factory=list)
    constructor: MethodNode = field(default_factory=MethodNode)
    methods: list[MethodNode] = field(default_factory=list)
    source_file: str = ""


# ---------------------------------------------------------------------------
# Primitive type names
# ---------------------------------------------------------------------------

PRIMITIVE_TYPE_NAMES: frozenset[str] = frozenset({
    "bigint",
    "boolean",
    "ByteString",
    "PubKey",
    "Sig",
    "Sha256",
    "Ripemd160",
    "Addr",
    "SigHashPreimage",
    "RabinSig",
    "RabinPubKey",
    "void",
    "Point",
})


def is_primitive_type(name: str) -> bool:
    """Return ``True`` if *name* is a recognized Runar primitive type."""
    return name in PRIMITIVE_TYPE_NAMES
