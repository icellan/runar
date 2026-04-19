"""Type checking pass for the Runar compiler.

Verifies type consistency of a validated Runar AST.
Direct port of ``compilers/go/frontend/typecheck.go``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from runar_compiler.frontend.ast_nodes import (
    AssignmentStmt,
    BigIntLiteral,
    BinaryExpr,
    BoolLiteral,
    ByteStringLiteral,
    CallExpr,
    ContractNode,
    CustomType,
    DecrementExpr,
    Expression,
    ExpressionStmt,
    FixedArrayType,
    ForStmt,
    Identifier,
    IfStmt,
    IncrementExpr,
    IndexAccessExpr,
    MemberExpr,
    MethodNode,
    PrimitiveType,
    PropertyAccessExpr,
    ReturnStmt,
    SourceLocation,
    Statement,
    TernaryExpr,
    TypeNode,
    UnaryExpr,
    VariableDeclStmt,
)
from runar_compiler.frontend.diagnostic import Diagnostic, Severity


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class TypeCheckResult:
    """Output of the type checking pass."""

    contract: ContractNode | None = None
    errors: list[Diagnostic] = field(default_factory=list)

    def error_strings(self) -> list[str]:
        """Return formatted error messages as plain strings."""
        return [d.format_message() for d in self.errors]


def type_check(contract: ContractNode) -> TypeCheckResult:
    """Type-check a Runar AST. Returns the same AST plus any errors."""
    checker = _TypeChecker(contract)

    checker.check_constructor()
    for method in contract.methods:
        checker.check_method(method)

    return TypeCheckResult(contract=contract, errors=checker.errors)


# ---------------------------------------------------------------------------
# Built-in function signatures
# ---------------------------------------------------------------------------

@dataclass
class FuncSig:
    """Signature of a function: parameter types and return type."""

    params: list[str]
    return_type: str


BUILTIN_FUNCTIONS: dict[str, FuncSig] = {
    "sha256":            FuncSig(params=["ByteString"], return_type="Sha256"),
    "ripemd160":         FuncSig(params=["ByteString"], return_type="Ripemd160"),
    "hash160":           FuncSig(params=["ByteString"], return_type="Ripemd160"),
    "hash256":           FuncSig(params=["ByteString"], return_type="Sha256"),
    "checkSig":          FuncSig(params=["Sig", "PubKey"], return_type="boolean"),
    "checkMultiSig":     FuncSig(params=["Sig[]", "PubKey[]"], return_type="boolean"),
    "assert":            FuncSig(params=["boolean"], return_type="void"),
    "len":               FuncSig(params=["ByteString"], return_type="bigint"),
    "cat":               FuncSig(params=["ByteString", "ByteString"], return_type="ByteString"),
    "substr":            FuncSig(params=["ByteString", "bigint", "bigint"], return_type="ByteString"),
    "num2bin":           FuncSig(params=["bigint", "bigint"], return_type="ByteString"),
    "bin2num":           FuncSig(params=["ByteString"], return_type="bigint"),
    "checkPreimage":     FuncSig(params=["SigHashPreimage"], return_type="boolean"),
    "verifyRabinSig":    FuncSig(params=["ByteString", "RabinSig", "ByteString", "RabinPubKey"], return_type="boolean"),
    "verifyWOTS":        FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_128s": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_128f": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_192s": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_192f": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_256s": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "verifySLHDSA_SHA2_256f": FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "ecAdd":              FuncSig(params=["Point", "Point"], return_type="Point"),
    "ecMul":              FuncSig(params=["Point", "bigint"], return_type="Point"),
    "ecMulGen":           FuncSig(params=["bigint"], return_type="Point"),
    "ecNegate":           FuncSig(params=["Point"], return_type="Point"),
    "ecOnCurve":          FuncSig(params=["Point"], return_type="boolean"),
    "ecModReduce":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "ecEncodeCompressed": FuncSig(params=["Point"], return_type="ByteString"),
    "ecMakePoint":        FuncSig(params=["bigint", "bigint"], return_type="Point"),
    "ecPointX":           FuncSig(params=["Point"], return_type="bigint"),
    "ecPointY":           FuncSig(params=["Point"], return_type="bigint"),
    # Elliptic curve operations (P-256 / NIST P-256 / secp256r1)
    "p256Add":              FuncSig(params=["P256Point", "P256Point"], return_type="P256Point"),
    "p256Mul":              FuncSig(params=["P256Point", "bigint"], return_type="P256Point"),
    "p256MulGen":           FuncSig(params=["bigint"], return_type="P256Point"),
    "p256Negate":           FuncSig(params=["P256Point"], return_type="P256Point"),
    "p256OnCurve":          FuncSig(params=["P256Point"], return_type="boolean"),
    "p256EncodeCompressed": FuncSig(params=["P256Point"], return_type="ByteString"),
    "verifyECDSA_P256":     FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    # Elliptic curve operations (P-384 / NIST P-384 / secp384r1)
    "p384Add":              FuncSig(params=["P384Point", "P384Point"], return_type="P384Point"),
    "p384Mul":              FuncSig(params=["P384Point", "bigint"], return_type="P384Point"),
    "p384MulGen":           FuncSig(params=["bigint"], return_type="P384Point"),
    "p384Negate":           FuncSig(params=["P384Point"], return_type="P384Point"),
    "p384OnCurve":          FuncSig(params=["P384Point"], return_type="boolean"),
    "p384EncodeCompressed": FuncSig(params=["P384Point"], return_type="ByteString"),
    "verifyECDSA_P384":     FuncSig(params=["ByteString", "ByteString", "ByteString"], return_type="boolean"),
    "sha256Compress":    FuncSig(params=["ByteString", "ByteString"], return_type="ByteString"),
    "sha256Finalize":    FuncSig(params=["ByteString", "ByteString", "bigint"], return_type="ByteString"),
    "blake3Compress":    FuncSig(params=["ByteString", "ByteString"], return_type="ByteString"),
    "blake3Hash":        FuncSig(params=["ByteString"], return_type="ByteString"),
    "bbFieldAdd":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bbFieldSub":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bbFieldMul":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bbFieldInv":        FuncSig(params=["bigint"], return_type="bigint"),
    "bbExt4Mul0":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Mul1":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Mul2":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Mul3":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Inv0":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Inv1":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Inv2":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "bbExt4Inv3":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    # KoalaBear field arithmetic (p = 2130706433)
    "kbFieldAdd":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "kbFieldSub":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "kbFieldMul":        FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "kbFieldInv":        FuncSig(params=["bigint"], return_type="bigint"),
    # KoalaBear quartic extension field (W = 3)
    "kbExt4Mul0":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Mul1":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Mul2":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Mul3":        FuncSig(params=["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Inv0":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Inv1":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Inv2":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    "kbExt4Inv3":        FuncSig(params=["bigint", "bigint", "bigint", "bigint"], return_type="bigint"),
    # BN254 field arithmetic
    "bn254FieldAdd":     FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bn254FieldSub":     FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bn254FieldMul":     FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "bn254FieldInv":     FuncSig(params=["bigint"], return_type="bigint"),
    "bn254FieldNeg":     FuncSig(params=["bigint"], return_type="bigint"),
    # BN254 G1 curve operations
    "bn254G1Add":        FuncSig(params=["Point", "Point"], return_type="Point"),
    "bn254G1ScalarMul":  FuncSig(params=["Point", "bigint"], return_type="Point"),
    "bn254G1Negate":     FuncSig(params=["Point"], return_type="Point"),
    "bn254G1OnCurve":    FuncSig(params=["Point"], return_type="boolean"),
    "merkleRootSha256":  FuncSig(params=["ByteString", "ByteString", "bigint", "bigint"], return_type="ByteString"),
    "merkleRootHash256": FuncSig(params=["ByteString", "ByteString", "bigint", "bigint"], return_type="ByteString"),
    "abs":               FuncSig(params=["bigint"], return_type="bigint"),
    "min":               FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "max":               FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "within":            FuncSig(params=["bigint", "bigint", "bigint"], return_type="boolean"),
    "safediv":           FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "safemod":           FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "clamp":             FuncSig(params=["bigint", "bigint", "bigint"], return_type="bigint"),
    "sign":              FuncSig(params=["bigint"], return_type="bigint"),
    "pow":               FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "mulDiv":            FuncSig(params=["bigint", "bigint", "bigint"], return_type="bigint"),
    "percentOf":         FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "sqrt":              FuncSig(params=["bigint"], return_type="bigint"),
    "gcd":               FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "divmod":            FuncSig(params=["bigint", "bigint"], return_type="bigint"),
    "log2":              FuncSig(params=["bigint"], return_type="bigint"),
    "bool":              FuncSig(params=["bigint"], return_type="boolean"),
    "reverseBytes":      FuncSig(params=["ByteString"], return_type="ByteString"),
    "left":              FuncSig(params=["ByteString", "bigint"], return_type="ByteString"),
    "right":             FuncSig(params=["ByteString", "bigint"], return_type="ByteString"),
    "int2str":           FuncSig(params=["bigint", "bigint"], return_type="ByteString"),
    "toByteString":      FuncSig(params=["ByteString"], return_type="ByteString"),
    "exit":              FuncSig(params=["boolean"], return_type="void"),
    "pack":              FuncSig(params=["bigint"], return_type="ByteString"),
    "unpack":            FuncSig(params=["ByteString"], return_type="bigint"),
    "extractVersion":       FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "extractHashPrevouts":  FuncSig(params=["SigHashPreimage"], return_type="Sha256"),
    "extractHashSequence":  FuncSig(params=["SigHashPreimage"], return_type="Sha256"),
    "extractOutpoint":      FuncSig(params=["SigHashPreimage"], return_type="ByteString"),
    "extractInputIndex":    FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "extractScriptCode":    FuncSig(params=["SigHashPreimage"], return_type="ByteString"),
    "extractAmount":        FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "extractSequence":      FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "extractOutputHash":    FuncSig(params=["SigHashPreimage"], return_type="Sha256"),
    "extractOutputs":       FuncSig(params=["SigHashPreimage"], return_type="Sha256"),
    "extractLocktime":      FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "extractSigHashType":   FuncSig(params=["SigHashPreimage"], return_type="bigint"),
    "split":                FuncSig(params=["ByteString", "bigint"], return_type="ByteString"),
    "buildChangeOutput":    FuncSig(params=["ByteString", "bigint"], return_type="ByteString"),
}


# ---------------------------------------------------------------------------
# Subtyping
# ---------------------------------------------------------------------------

_BYTESTRING_SUBTYPES: frozenset[str] = frozenset({
    "ByteString",
    "PubKey",
    "Sig",
    "Sha256",
    "Ripemd160",
    "Addr",
    "SigHashPreimage",
    "Point",
    "P256Point",
    "P384Point",
})

_BIGINT_SUBTYPES: frozenset[str] = frozenset({
    "bigint",
    "RabinSig",
    "RabinPubKey",
})


def is_subtype(actual: str, expected: str) -> bool:
    """Return True if *actual* is a subtype of *expected*."""
    if actual == expected:
        return True
    # <inferred> and <unknown> are compatible with anything
    if actual in ("<inferred>", "<unknown>"):
        return True
    if expected in ("<inferred>", "<unknown>"):
        return True
    if expected == "ByteString" and actual in _BYTESTRING_SUBTYPES:
        return True
    if expected == "bigint" and actual in _BIGINT_SUBTYPES:
        return True
    if expected.endswith("[]") and actual.endswith("[]"):
        return is_subtype(actual[:-2], expected[:-2])
    return False


def is_bigint_family(t: str) -> bool:
    """Return True if *t* belongs to the bigint type family."""
    return t in _BIGINT_SUBTYPES


def _is_byte_family(t: str) -> bool:
    """Return True if *t* belongs to the ByteString type family."""
    return t in _BYTESTRING_SUBTYPES


# ---------------------------------------------------------------------------
# Type environment
# ---------------------------------------------------------------------------

class _TypeEnv:
    """Scoped type environment with push/pop semantics."""

    def __init__(self) -> None:
        self._scopes: list[dict[str, str]] = [{}]

    def push_scope(self) -> None:
        self._scopes.append({})

    def pop_scope(self) -> None:
        if self._scopes:
            self._scopes.pop()

    def define(self, name: str, typ: str) -> None:
        self._scopes[-1][name] = typ

    def lookup(self, name: str) -> tuple[str, bool]:
        for scope in reversed(self._scopes):
            if name in scope:
                return scope[name], True
        return "", False


# ---------------------------------------------------------------------------
# Affine types
# ---------------------------------------------------------------------------

_AFFINE_TYPES: frozenset[str] = frozenset({"Sig", "SigHashPreimage"})

_CONSUMING_FUNCTIONS: dict[str, list[int]] = {
    "checkSig":      [0],
    "checkMultiSig": [0],
    "checkPreimage": [0],
}


# ---------------------------------------------------------------------------
# Type checker
# ---------------------------------------------------------------------------

class _TypeChecker:
    def __init__(self, contract: ContractNode) -> None:
        self.contract = contract
        self.errors: list[Diagnostic] = []
        self.prop_types: dict[str, str] = {}
        self.method_sigs: dict[str, FuncSig] = {}
        self.consumed_values: dict[str, bool] = {}
        self._current_method_loc: SourceLocation | None = None
        self._current_stmt_loc: SourceLocation | None = None

        for prop in contract.properties:
            self.prop_types[prop.name] = _type_node_to_string(prop.type)

        # For StatefulSmartContract, add the implicit txPreimage property
        if contract.parent_class == "StatefulSmartContract":
            self.prop_types["txPreimage"] = "SigHashPreimage"

        for method in contract.methods:
            params = [_type_node_to_string(p.type) for p in method.params]
            ret_type = "void"
            if method.visibility != "public":
                ret_type = _infer_method_return_type(method)
            self.method_sigs[method.name] = FuncSig(params=params, return_type=ret_type)

    def _add_error(self, msg: str) -> None:
        loc = self._current_stmt_loc if self._current_stmt_loc is not None else self._current_method_loc
        self.errors.append(Diagnostic(message=msg, severity=Severity.ERROR, loc=loc))

    def check_constructor(self) -> None:
        ctor = self.contract.constructor
        env = _TypeEnv()

        # Set current method location for diagnostics
        self._current_method_loc = ctor.source_location

        # Reset affine tracking
        self.consumed_values = {}

        for param in ctor.params:
            env.define(param.name, _type_node_to_string(param.type))
        for prop in self.contract.properties:
            env.define(prop.name, _type_node_to_string(prop.type))

        self._check_statements(ctor.body, env)

    def check_method(self, method: MethodNode) -> None:
        env = _TypeEnv()

        # Set current method location for diagnostics
        self._current_method_loc = method.source_location

        # Reset affine tracking
        self.consumed_values = {}

        for param in method.params:
            env.define(param.name, _type_node_to_string(param.type))

        self._check_statements(method.body, env)

    def _check_statements(self, stmts: list[Statement], env: _TypeEnv) -> None:
        for stmt in stmts:
            self._check_statement(stmt, env)

    def _check_statement(self, stmt: Statement, env: _TypeEnv) -> None:
        # Set statement-level source location for diagnostics
        prev_stmt_loc = self._current_stmt_loc
        stmt_loc = _stmt_source_location(stmt)
        if stmt_loc is not None:
            self._current_stmt_loc = stmt_loc

        if isinstance(stmt, VariableDeclStmt):
            init_type = self._infer_expr_type(stmt.init, env)
            if stmt.type is not None:
                declared_type = _type_node_to_string(stmt.type)
                if not is_subtype(init_type, declared_type):
                    self._add_error(
                        f"type '{init_type}' is not assignable to type '{declared_type}'"
                    )
                env.define(stmt.name, declared_type)
            else:
                env.define(stmt.name, init_type)

        elif isinstance(stmt, AssignmentStmt):
            target_type = self._infer_expr_type(stmt.target, env)
            value_type = self._infer_expr_type(stmt.value, env)
            if not is_subtype(value_type, target_type):
                self._add_error(
                    f"type '{value_type}' is not assignable to type '{target_type}'"
                )

        elif isinstance(stmt, IfStmt):
            cond_type = self._infer_expr_type(stmt.condition, env)
            if cond_type != "boolean":
                self._add_error(f"if condition must be boolean, got '{cond_type}'")
            env.push_scope()
            self._check_statements(stmt.then, env)
            env.pop_scope()
            if stmt.else_:
                env.push_scope()
                self._check_statements(stmt.else_, env)
                env.pop_scope()

        elif isinstance(stmt, ForStmt):
            env.push_scope()
            self._check_statement(stmt.init, env)
            cond_type = self._infer_expr_type(stmt.condition, env)
            if cond_type != "boolean":
                self._add_error(
                    f"for loop condition must be boolean, got '{cond_type}'"
                )
            self._check_statements(stmt.body, env)
            env.pop_scope()

        elif isinstance(stmt, ExpressionStmt):
            self._infer_expr_type(stmt.expr, env)

        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                self._infer_expr_type(stmt.value, env)

        # Restore previous statement location
        self._current_stmt_loc = prev_stmt_loc

    # -------------------------------------------------------------------
    # Type inference
    # -------------------------------------------------------------------

    def _infer_expr_type(self, expr: Expression | None, env: _TypeEnv) -> str:
        if expr is None:
            return "<unknown>"

        if isinstance(expr, BigIntLiteral):
            return "bigint"
        if isinstance(expr, BoolLiteral):
            return "boolean"
        if isinstance(expr, ByteStringLiteral):
            return "ByteString"

        if isinstance(expr, Identifier):
            if expr.name == "this":
                return "<this>"
            if expr.name == "super":
                return "<super>"
            t, found = env.lookup(expr.name)
            if found:
                return t
            if expr.name in BUILTIN_FUNCTIONS:
                return "<builtin>"
            return "<unknown>"

        if isinstance(expr, PropertyAccessExpr):
            if expr.property in self.prop_types:
                return self.prop_types[expr.property]
            return "<unknown>"

        if isinstance(expr, MemberExpr):
            obj_type = self._infer_expr_type(expr.object, env)
            if obj_type == "<this>":
                if expr.property in self.prop_types:
                    return self.prop_types[expr.property]
                if expr.property in self.method_sigs:
                    return "<method>"
                if expr.property == "getStateScript":
                    return "<method>"
                return "<unknown>"
            if isinstance(expr.object, Identifier) and expr.object.name == "SigHash":
                return "bigint"
            return "<unknown>"

        if isinstance(expr, BinaryExpr):
            return self._check_binary_expr(expr, env)

        if isinstance(expr, UnaryExpr):
            return self._check_unary_expr(expr, env)

        if isinstance(expr, CallExpr):
            return self._check_call_expr(expr, env)

        if isinstance(expr, TernaryExpr):
            cond_type = self._infer_expr_type(expr.condition, env)
            if cond_type != "boolean":
                self._add_error(
                    f"ternary condition must be boolean, got '{cond_type}'"
                )
            cons_type = self._infer_expr_type(expr.consequent, env)
            alt_type = self._infer_expr_type(expr.alternate, env)
            if cons_type != alt_type:
                if is_subtype(alt_type, cons_type):
                    return cons_type
                if is_subtype(cons_type, alt_type):
                    return alt_type
            return cons_type

        if isinstance(expr, IndexAccessExpr):
            obj_type = self._infer_expr_type(expr.object, env)
            index_type = self._infer_expr_type(expr.index, env)
            if not is_bigint_family(index_type):
                self._add_error(f"array index must be bigint, got '{index_type}'")
            if obj_type.endswith("[]"):
                return obj_type[:-2]
            return "<unknown>"

        if isinstance(expr, IncrementExpr):
            operand_type = self._infer_expr_type(expr.operand, env)
            if not is_bigint_family(operand_type):
                self._add_error(f"++ operator requires bigint, got '{operand_type}'")
            return "bigint"

        if isinstance(expr, DecrementExpr):
            operand_type = self._infer_expr_type(expr.operand, env)
            if not is_bigint_family(operand_type):
                self._add_error(f"-- operator requires bigint, got '{operand_type}'")
            return "bigint"

        return "<unknown>"

    # -------------------------------------------------------------------
    # Binary expression type checking
    # -------------------------------------------------------------------

    def _check_binary_expr(self, e: BinaryExpr, env: _TypeEnv) -> str:
        left_type = self._infer_expr_type(e.left, env)
        right_type = self._infer_expr_type(e.right, env)

        # ByteString concatenation: ByteString + ByteString -> ByteString (via OP_CAT)
        if e.op == "+" and _is_byte_family(left_type) and _is_byte_family(right_type):
            return "ByteString"

        # Arithmetic: bigint x bigint -> bigint
        if e.op in ("+", "-", "*", "/", "%"):
            if not is_bigint_family(left_type):
                self._add_error(
                    f"left operand of '{e.op}' must be bigint, got '{left_type}'"
                )
            if not is_bigint_family(right_type):
                self._add_error(
                    f"right operand of '{e.op}' must be bigint, got '{right_type}'"
                )
            return "bigint"

        if e.op in ("<", "<=", ">", ">="):
            if not is_bigint_family(left_type):
                self._add_error(
                    f"left operand of '{e.op}' must be bigint, got '{left_type}'"
                )
            if not is_bigint_family(right_type):
                self._add_error(
                    f"right operand of '{e.op}' must be bigint, got '{right_type}'"
                )
            return "boolean"

        if e.op in ("===", "!=="):
            compatible = (
                is_subtype(left_type, right_type)
                or is_subtype(right_type, left_type)
                or (left_type in _BYTESTRING_SUBTYPES and right_type in _BYTESTRING_SUBTYPES)
                or (left_type in _BIGINT_SUBTYPES and right_type in _BIGINT_SUBTYPES)
            )
            if not compatible:
                if left_type != "<unknown>" and right_type != "<unknown>":
                    self._add_error(
                        f"cannot compare '{left_type}' and '{right_type}' with '{e.op}'"
                    )
            return "boolean"

        if e.op in ("&&", "||"):
            if left_type != "boolean" and left_type != "<unknown>":
                self._add_error(
                    f"left operand of '{e.op}' must be boolean, got '{left_type}'"
                )
            if right_type != "boolean" and right_type != "<unknown>":
                self._add_error(
                    f"right operand of '{e.op}' must be boolean, got '{right_type}'"
                )
            return "boolean"

        if e.op in ("<<", ">>"):
            if not is_bigint_family(left_type):
                self._add_error(
                    f"left operand of '{e.op}' must be bigint, got '{left_type}'"
                )
            if not is_bigint_family(right_type):
                self._add_error(
                    f"right operand of '{e.op}' must be bigint, got '{right_type}'"
                )
            return "bigint"

        # Bitwise operators: bigint x bigint -> bigint, or ByteString x ByteString -> ByteString
        if e.op in ("&", "|", "^"):
            if _is_byte_family(left_type) and _is_byte_family(right_type):
                return "ByteString"
            if not is_bigint_family(left_type):
                self._add_error(
                    f"left operand of '{e.op}' must be bigint or ByteString, got '{left_type}'"
                )
            if not is_bigint_family(right_type):
                self._add_error(
                    f"right operand of '{e.op}' must be bigint or ByteString, got '{right_type}'"
                )
            return "bigint"

        return "<unknown>"

    # -------------------------------------------------------------------
    # Unary expression type checking
    # -------------------------------------------------------------------

    def _check_unary_expr(self, e: UnaryExpr, env: _TypeEnv) -> str:
        operand_type = self._infer_expr_type(e.operand, env)

        if e.op == "!":
            if operand_type != "boolean" and operand_type != "<unknown>":
                self._add_error(
                    f"operand of '!' must be boolean, got '{operand_type}'"
                )
            return "boolean"

        if e.op == "-":
            if not is_bigint_family(operand_type):
                self._add_error(
                    f"operand of unary '-' must be bigint, got '{operand_type}'"
                )
            return "bigint"

        if e.op == "~":
            if _is_byte_family(operand_type):
                return "ByteString"
            if not is_bigint_family(operand_type):
                self._add_error(
                    f"operand of '~' must be bigint or ByteString, got '{operand_type}'"
                )
            return "bigint"

        return "<unknown>"

    # -------------------------------------------------------------------
    # Call expression type checking
    # -------------------------------------------------------------------

    def _check_call_expr(self, e: CallExpr, env: _TypeEnv) -> str:
        # super() call
        if isinstance(e.callee, Identifier) and e.callee.name == "super":
            for arg in e.args:
                self._infer_expr_type(arg, env)
            return "void"

        # Direct builtin call
        if isinstance(e.callee, Identifier):
            name = e.callee.name
            if name in BUILTIN_FUNCTIONS:
                return self._check_call_args(name, BUILTIN_FUNCTIONS[name], e.args, env)
            # Check if it's a known contract method
            if name in self.method_sigs:
                return self._check_call_args(name, self.method_sigs[name], e.args, env)
            # Check if it's a local variable
            _, found = env.lookup(name)
            if found:
                for arg in e.args:
                    self._infer_expr_type(arg, env)
                return "<unknown>"
            self._add_error(
                f"unknown function '{name}' -- only Runar built-in functions "
                f"and contract methods are allowed"
            )
            for arg in e.args:
                self._infer_expr_type(arg, env)
            return "<unknown>"

        # this.method() via PropertyAccessExpr
        if isinstance(e.callee, PropertyAccessExpr):
            prop = e.callee.property
            if prop == "getStateScript":
                return "ByteString"
            if prop == "addOutput":
                for arg in e.args:
                    self._infer_expr_type(arg, env)
                return "void"
            if prop == "addRawOutput":
                for arg in e.args:
                    self._infer_expr_type(arg, env)
                return "void"
            if prop == "addDataOutput":
                for arg in e.args:
                    self._infer_expr_type(arg, env)
                return "void"
            if prop in self.method_sigs:
                return self._check_call_args(prop, self.method_sigs[prop], e.args, env)
            self._add_error(
                f"unknown method 'this.{prop}' -- only Runar built-in methods "
                f"and contract methods are allowed"
            )
            for arg in e.args:
                self._infer_expr_type(arg, env)
            return "<unknown>"

        # this.method() via MemberExpr
        if isinstance(e.callee, MemberExpr):
            obj_type = self._infer_expr_type(e.callee.object, env)
            is_this = obj_type == "<this>" or (
                isinstance(e.callee.object, Identifier) and e.callee.object.name == "this"
            )
            if is_this:
                if e.callee.property == "getStateScript":
                    return "ByteString"
                if e.callee.property == "addOutput":
                    for arg in e.args:
                        self._infer_expr_type(arg, env)
                    return "void"
                if e.callee.property == "addRawOutput":
                    for arg in e.args:
                        self._infer_expr_type(arg, env)
                    return "void"
                if e.callee.property == "addDataOutput":
                    for arg in e.args:
                        self._infer_expr_type(arg, env)
                    return "void"
                if e.callee.property in self.method_sigs:
                    return self._check_call_args(
                        e.callee.property,
                        self.method_sigs[e.callee.property],
                        e.args,
                        env,
                    )
            # Not this.method -- reject (e.g. Math.floor)
            obj_name = "<expr>"
            if isinstance(e.callee.object, Identifier):
                obj_name = e.callee.object.name
            self._add_error(
                f"unknown function '{obj_name}.{e.callee.property}' -- only Runar "
                f"built-in functions and contract methods are allowed"
            )
            for arg in e.args:
                self._infer_expr_type(arg, env)
            return "<unknown>"

        # Fallback -- unknown callee shape
        self._add_error(
            "unsupported function call expression -- only Runar built-in "
            "functions and contract methods are allowed"
        )
        self._infer_expr_type(e.callee, env)
        for arg in e.args:
            self._infer_expr_type(arg, env)
        return "<unknown>"

    # -------------------------------------------------------------------
    # Argument checking
    # -------------------------------------------------------------------

    def _check_call_args(
        self,
        func_name: str,
        sig: FuncSig,
        args: list[Expression],
        env: _TypeEnv,
    ) -> str:
        # assert special case
        if func_name == "assert":
            if len(args) < 1 or len(args) > 2:
                self._add_error(
                    f"assert() expects 1 or 2 arguments, got {len(args)}"
                )
            if len(args) >= 1:
                cond_type = self._infer_expr_type(args[0], env)
                if cond_type != "boolean" and cond_type != "<unknown>":
                    self._add_error(
                        f"assert() condition must be boolean, got '{cond_type}'"
                    )
            if len(args) >= 2:
                self._infer_expr_type(args[1], env)
            return sig.return_type

        # checkMultiSig special case
        if func_name == "checkMultiSig":
            for arg in args:
                self._infer_expr_type(arg, env)
            self._check_affine_consumption(func_name, args, env)
            return sig.return_type

        # Standard arg count check
        if len(args) != len(sig.params):
            self._add_error(
                f"{func_name}() expects {len(sig.params)} argument(s), got {len(args)}"
            )

        count = min(len(args), len(sig.params))

        for i in range(count):
            arg_type = self._infer_expr_type(args[i], env)
            expected_type = sig.params[i]
            if not is_subtype(arg_type, expected_type) and arg_type != "<unknown>":
                self._add_error(
                    f"argument {i + 1} of {func_name}(): expected '{expected_type}', "
                    f"got '{arg_type}'"
                )

        for i in range(count, len(args)):
            self._infer_expr_type(args[i], env)

        # Affine type enforcement
        self._check_affine_consumption(func_name, args, env)

        return sig.return_type

    # -------------------------------------------------------------------
    # Affine consumption
    # -------------------------------------------------------------------

    def _check_affine_consumption(
        self,
        func_name: str,
        args: list[Expression],
        env: _TypeEnv,
    ) -> None:
        consumed_indices = _CONSUMING_FUNCTIONS.get(func_name)
        if consumed_indices is None:
            return

        for param_index in consumed_indices:
            if param_index >= len(args):
                continue

            arg = args[param_index]
            if not isinstance(arg, Identifier):
                continue

            arg_type, found = env.lookup(arg.name)
            if not found or arg_type not in _AFFINE_TYPES:
                continue

            if self.consumed_values.get(arg.name, False):
                self._add_error(
                    f"affine value '{arg.name}' has already been consumed"
                )
            else:
                self.consumed_values[arg.name] = True


# ---------------------------------------------------------------------------
# Private method return type inference
# ---------------------------------------------------------------------------

def _infer_method_return_type(method: MethodNode) -> str:
    """Walk a private method body, collect return types, and unify them."""
    return_types = _collect_return_types(method.body)
    if not return_types:
        return "void"

    first = return_types[0]
    if all(t == first for t in return_types):
        return first

    # Check if all are in the bigint family
    if all(t in _BIGINT_SUBTYPES for t in return_types):
        return "bigint"

    # Check if all are in the ByteString family
    if all(t in _BYTESTRING_SUBTYPES for t in return_types):
        return "ByteString"

    # Check if all are boolean
    if all(t == "boolean" for t in return_types):
        return "boolean"

    return first


def _collect_return_types(stmts: list[Statement]) -> list[str]:
    """Recursively collect inferred types from return statements."""
    types: list[str] = []
    for stmt in stmts:
        if isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                types.append(_infer_expr_type_static(stmt.value))
        elif isinstance(stmt, IfStmt):
            types.extend(_collect_return_types(stmt.then))
            if stmt.else_:
                types.extend(_collect_return_types(stmt.else_))
        elif isinstance(stmt, ForStmt):
            types.extend(_collect_return_types(stmt.body))
    return types


def _infer_expr_type_static(expr: Expression | None) -> str:
    """Lightweight expression type inference without a type environment.

    Used for inferring return types of private methods before the full
    type-check pass runs.
    """
    if expr is None:
        return "<unknown>"

    if isinstance(expr, BigIntLiteral):
        return "bigint"
    if isinstance(expr, BoolLiteral):
        return "boolean"
    if isinstance(expr, ByteStringLiteral):
        return "ByteString"

    if isinstance(expr, Identifier):
        if expr.name in ("true", "false"):
            return "boolean"
        return "<unknown>"

    if isinstance(expr, BinaryExpr):
        if expr.op in ("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"):
            return "bigint"
        # Comparison, equality, logical operators -> boolean
        return "boolean"

    if isinstance(expr, UnaryExpr):
        if expr.op == "!":
            return "boolean"
        return "bigint"  # '-' and '~'

    if isinstance(expr, CallExpr):
        if isinstance(expr.callee, Identifier):
            sig = BUILTIN_FUNCTIONS.get(expr.callee.name)
            if sig is not None:
                return sig.return_type
        if isinstance(expr.callee, PropertyAccessExpr):
            sig = BUILTIN_FUNCTIONS.get(expr.callee.property)
            if sig is not None:
                return sig.return_type
        return "<unknown>"

    if isinstance(expr, TernaryExpr):
        cons_type = _infer_expr_type_static(expr.consequent)
        if cons_type != "<unknown>":
            return cons_type
        return _infer_expr_type_static(expr.alternate)

    if isinstance(expr, (IncrementExpr, DecrementExpr)):
        return "bigint"

    return "<unknown>"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _type_node_to_string(node: TypeNode | None) -> str:
    """Convert a type node to its string representation."""
    if node is None:
        return "<unknown>"
    if isinstance(node, PrimitiveType):
        return node.name
    if isinstance(node, FixedArrayType):
        return _type_node_to_string(node.element) + "[]"
    if isinstance(node, CustomType):
        return node.name
    return "<unknown>"


def _stmt_source_location(stmt: Statement) -> SourceLocation | None:
    """Extract the SourceLocation from a statement node, if it has a meaningful value."""
    loc = getattr(stmt, "source_location", None)
    if loc is not None and (loc.file or loc.line > 0):
        return loc
    return None
