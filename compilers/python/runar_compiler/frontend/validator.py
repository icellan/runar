"""Validation pass for the Runar compiler.

Checks the AST against language subset constraints WITHOUT modifying it.
Direct port of ``compilers/go/frontend/validator.go``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from runar_compiler.frontend.ast_nodes import (
    AssignmentStmt,
    BigIntLiteral,
    BinaryExpr,
    BoolLiteral,
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Output of the validation pass."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate(contract: ContractNode) -> ValidationResult:
    """Validate a Runar AST against language subset constraints.

    Does NOT modify the AST; only reports errors and warnings.
    """
    ctx = _ValidationContext(contract=contract)

    ctx.validate_properties()
    ctx.validate_constructor()
    ctx.validate_methods()
    ctx.check_no_recursion()

    return ValidationResult(errors=ctx.errors, warnings=ctx.warnings)


# ---------------------------------------------------------------------------
# Valid property types
# ---------------------------------------------------------------------------

_VALID_PROP_TYPES: frozenset[str] = frozenset({
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
    "Point",
})


# ---------------------------------------------------------------------------
# Validation context
# ---------------------------------------------------------------------------

@dataclass
class _ValidationContext:
    contract: ContractNode
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def _add_error(self, msg: str) -> None:
        self.errors.append(msg)

    # -------------------------------------------------------------------
    # Property validation
    # -------------------------------------------------------------------

    def validate_properties(self) -> None:
        for prop in self.contract.properties:
            self._validate_property_type(prop.type, prop.source_location)

            # V27: txPreimage is an implicit property of StatefulSmartContract
            if self.contract.parent_class == "StatefulSmartContract" and prop.name == "txPreimage":
                self._add_error(
                    "'txPreimage' is an implicit property of StatefulSmartContract "
                    "and must not be declared"
                )

        # SmartContract requires all properties to be readonly
        if self.contract.parent_class == "SmartContract":
            for prop in self.contract.properties:
                if not prop.readonly:
                    self._add_error(
                        f"Property '{prop.name}' in SmartContract must be declared readonly"
                    )

        # V26: Warn if StatefulSmartContract has no mutable properties
        if self.contract.parent_class == "StatefulSmartContract":
            has_mutable = any(not p.readonly for p in self.contract.properties)
            if not has_mutable:
                self.warnings.append(
                    "StatefulSmartContract has no mutable properties; "
                    "consider using SmartContract instead"
                )

    def _validate_property_type(self, t: TypeNode | None, loc: SourceLocation) -> None:
        if t is None:
            return
        if isinstance(t, PrimitiveType):
            if t.name not in _VALID_PROP_TYPES:
                if t.name == "void":
                    self._add_error(
                        f"property type 'void' is not valid at {loc.file}:{loc.line}"
                    )
        elif isinstance(t, FixedArrayType):
            if t.length <= 0:
                self._add_error(
                    f"FixedArray length must be a positive integer at {loc.file}:{loc.line}"
                )
            self._validate_property_type(t.element, loc)
        elif isinstance(t, CustomType):
            self._add_error(
                f"unsupported type '{t.name}' in property declaration at {loc.file}:{loc.line}"
            )

    # -------------------------------------------------------------------
    # Constructor validation
    # -------------------------------------------------------------------

    def validate_constructor(self) -> None:
        ctor = self.contract.constructor
        prop_names: set[str] = {p.name for p in self.contract.properties}

        # Check super() as first statement
        if len(ctor.body) == 0:
            self._add_error("constructor must call super() as its first statement")
            return

        if not _is_super_call(ctor.body[0]):
            self._add_error("constructor must call super() as its first statement")

        # Check all properties are assigned
        assigned_props: set[str] = set()
        for stmt in ctor.body:
            if isinstance(stmt, AssignmentStmt):
                if isinstance(stmt.target, PropertyAccessExpr):
                    assigned_props.add(stmt.target.property)

        # Properties with initializers don't need constructor assignments
        props_with_init = {
            p.name for p in self.contract.properties if p.initializer is not None
        }

        for name in prop_names:
            if name not in assigned_props and name not in props_with_init:
                self._add_error(
                    f"property '{name}' must be assigned in the constructor"
                )

        # Validate constructor body
        for stmt in ctor.body:
            self._validate_statement(stmt)

    # -------------------------------------------------------------------
    # Method validation
    # -------------------------------------------------------------------

    def validate_methods(self) -> None:
        for method in self.contract.methods:
            self._validate_method(method)

    def _validate_method(self, method) -> None:
        # Public methods must end with assert() (unless StatefulSmartContract,
        # where the compiler auto-injects the final assert)
        if (
            method.visibility == "public"
            and self.contract.parent_class != "StatefulSmartContract"
        ):
            if not _ends_with_assert(method.body):
                self._add_error(
                    f"public method '{method.name}' must end with an assert() call"
                )

        # V24/V25: Warn on manual preimage/state-script boilerplate in StatefulSmartContract
        if self.contract.parent_class == "StatefulSmartContract" and method.visibility == "public":
            _warn_manual_preimage_usage(method, self.warnings)

        # Validate statements
        for stmt in method.body:
            self._validate_statement(stmt)

    # -------------------------------------------------------------------
    # Statement validation
    # -------------------------------------------------------------------

    def _validate_statement(self, stmt: Statement) -> None:
        if isinstance(stmt, VariableDeclStmt):
            self._validate_expression(stmt.init)
        elif isinstance(stmt, AssignmentStmt):
            self._validate_expression(stmt.target)
            self._validate_expression(stmt.value)
        elif isinstance(stmt, IfStmt):
            self._validate_expression(stmt.condition)
            for st in stmt.then:
                self._validate_statement(st)
            for st in stmt.else_:
                self._validate_statement(st)
        elif isinstance(stmt, ForStmt):
            self._validate_for_statement(stmt)
        elif isinstance(stmt, ExpressionStmt):
            self._validate_expression(stmt.expr)
        elif isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                self._validate_expression(stmt.value)

    def _validate_for_statement(self, stmt: ForStmt) -> None:
        self._validate_expression(stmt.condition)

        # Check constant bounds
        if isinstance(stmt.condition, BinaryExpr):
            if not _is_compile_time_constant(stmt.condition.right):
                self._add_error("for loop bound must be a compile-time constant")

        self._validate_expression(stmt.init.init)
        for s in stmt.body:
            self._validate_statement(s)

    # -------------------------------------------------------------------
    # Expression validation
    # -------------------------------------------------------------------

    def _validate_expression(self, expr: Expression | None) -> None:
        if expr is None:
            return
        if isinstance(expr, BinaryExpr):
            self._validate_expression(expr.left)
            self._validate_expression(expr.right)
        elif isinstance(expr, UnaryExpr):
            self._validate_expression(expr.operand)
        elif isinstance(expr, CallExpr):
            self._validate_expression(expr.callee)
            for arg in expr.args:
                self._validate_expression(arg)
        elif isinstance(expr, MemberExpr):
            self._validate_expression(expr.object)
        elif isinstance(expr, TernaryExpr):
            self._validate_expression(expr.condition)
            self._validate_expression(expr.consequent)
            self._validate_expression(expr.alternate)
        elif isinstance(expr, IndexAccessExpr):
            self._validate_expression(expr.object)
            self._validate_expression(expr.index)
        elif isinstance(expr, IncrementExpr):
            self._validate_expression(expr.operand)
        elif isinstance(expr, DecrementExpr):
            self._validate_expression(expr.operand)

    # -------------------------------------------------------------------
    # Recursion detection
    # -------------------------------------------------------------------

    def check_no_recursion(self) -> None:
        call_graph: dict[str, set[str]] = {}
        method_names: set[str] = set()

        for method in self.contract.methods:
            method_names.add(method.name)
            calls: set[str] = set()
            _collect_method_calls(method.body, calls)
            call_graph[method.name] = calls

        # Check for cycles using DFS
        for method in self.contract.methods:
            visited: set[str] = set()
            stack: set[str] = set()
            if _has_cycle(method.name, call_graph, method_names, visited, stack):
                self._add_error(
                    f"recursion detected: method '{method.name}' calls itself "
                    f"directly or indirectly"
                )


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _is_super_call(stmt: Statement) -> bool:
    if not isinstance(stmt, ExpressionStmt):
        return False
    if not isinstance(stmt.expr, CallExpr):
        return False
    callee = stmt.expr.callee
    # Accept both Identifier("super") and MemberExpr(Identifier("super"), "")
    if isinstance(callee, Identifier):
        return callee.name == "super"
    if isinstance(callee, MemberExpr):
        return isinstance(callee.object, Identifier) and callee.object.name == "super"
    return False


def _ends_with_assert(body: list[Statement]) -> bool:
    if len(body) == 0:
        return False
    last = body[-1]

    if isinstance(last, ExpressionStmt):
        return _is_assert_call(last.expr)

    if isinstance(last, IfStmt):
        then_ends = _ends_with_assert(last.then)
        else_ends = len(last.else_) > 0 and _ends_with_assert(last.else_)
        return then_ends and else_ends

    return False


def _is_assert_call(expr: Expression | None) -> bool:
    if not isinstance(expr, CallExpr):
        return False
    if not isinstance(expr.callee, Identifier):
        return False
    return expr.callee.name == "assert"


def _is_compile_time_constant(expr: Expression | None) -> bool:
    if expr is None:
        return False
    if isinstance(expr, BigIntLiteral):
        return True
    if isinstance(expr, BoolLiteral):
        return True
    if isinstance(expr, Identifier):
        return True  # trust it's a const
    if isinstance(expr, UnaryExpr):
        if expr.op == "-":
            return _is_compile_time_constant(expr.operand)
    return False


# ---------------------------------------------------------------------------
# V24/V25: warn on manual preimage/state-script usage
# ---------------------------------------------------------------------------

def _warn_manual_preimage_usage(method, warnings: list[str]) -> None:
    """Walk method body and warn on checkPreimage() or this.getStateScript() calls."""

    def visitor(expr: Expression) -> None:
        if isinstance(expr, CallExpr):
            # V24: bare checkPreimage(...) call
            if isinstance(expr.callee, Identifier) and expr.callee.name == "checkPreimage":
                warnings.append(
                    f"StatefulSmartContract auto-injects checkPreimage(); calling it manually "
                    f"in '{method.name}' will cause a duplicate verification"
                )
            # V24: this.checkPreimage(...) call via PropertyAccessExpr or MemberExpr
            callee_prop = _callee_property(expr.callee)
            if callee_prop == "checkPreimage":
                warnings.append(
                    f"StatefulSmartContract auto-injects checkPreimage(); calling it manually "
                    f"in '{method.name}' will cause a duplicate verification"
                )
            # V25: this.getStateScript() call
            if callee_prop == "getStateScript":
                warnings.append(
                    f"StatefulSmartContract auto-injects state continuation; calling "
                    f"getStateScript() manually in '{method.name}' is redundant"
                )

    _walk_expressions_in_body(method.body, visitor)


def _callee_property(callee: Expression | None) -> str | None:
    """Return the property name if callee is a property access (PropertyAccessExpr or MemberExpr)."""
    if callee is None:
        return None
    if isinstance(callee, PropertyAccessExpr):
        return callee.property
    if isinstance(callee, MemberExpr):
        return callee.property
    return None


def _walk_expressions_in_body(stmts: list[Statement], visitor) -> None:
    for stmt in stmts:
        _walk_expressions_in_stmt(stmt, visitor)


def _walk_expressions_in_stmt(stmt: Statement, visitor) -> None:
    if isinstance(stmt, ExpressionStmt):
        _walk_expr(stmt.expr, visitor)
    elif isinstance(stmt, VariableDeclStmt):
        _walk_expr(stmt.init, visitor)
    elif isinstance(stmt, AssignmentStmt):
        _walk_expr(stmt.target, visitor)
        _walk_expr(stmt.value, visitor)
    elif isinstance(stmt, IfStmt):
        _walk_expr(stmt.condition, visitor)
        _walk_expressions_in_body(stmt.then, visitor)
        _walk_expressions_in_body(stmt.else_, visitor)
    elif isinstance(stmt, ForStmt):
        _walk_expr(stmt.condition, visitor)
        _walk_expressions_in_body(stmt.body, visitor)
    elif isinstance(stmt, ReturnStmt):
        if stmt.value is not None:
            _walk_expr(stmt.value, visitor)


def _walk_expr(expr: Expression | None, visitor) -> None:
    if expr is None:
        return
    visitor(expr)
    if isinstance(expr, BinaryExpr):
        _walk_expr(expr.left, visitor)
        _walk_expr(expr.right, visitor)
    elif isinstance(expr, UnaryExpr):
        _walk_expr(expr.operand, visitor)
    elif isinstance(expr, CallExpr):
        _walk_expr(expr.callee, visitor)
        for arg in expr.args:
            _walk_expr(arg, visitor)
    elif isinstance(expr, MemberExpr):
        _walk_expr(expr.object, visitor)
    elif isinstance(expr, TernaryExpr):
        _walk_expr(expr.condition, visitor)
        _walk_expr(expr.consequent, visitor)
        _walk_expr(expr.alternate, visitor)
    elif isinstance(expr, IndexAccessExpr):
        _walk_expr(expr.object, visitor)
        _walk_expr(expr.index, visitor)
    elif isinstance(expr, IncrementExpr):
        _walk_expr(expr.operand, visitor)
    elif isinstance(expr, DecrementExpr):
        _walk_expr(expr.operand, visitor)


# ---------------------------------------------------------------------------
# Recursion detection helpers
# ---------------------------------------------------------------------------

def _collect_method_calls(stmts: list[Statement], calls: set[str]) -> None:
    for stmt in stmts:
        _collect_method_calls_in_stmt(stmt, calls)


def _collect_method_calls_in_stmt(stmt: Statement, calls: set[str]) -> None:
    if isinstance(stmt, ExpressionStmt):
        _collect_method_calls_in_expr(stmt.expr, calls)
    elif isinstance(stmt, VariableDeclStmt):
        _collect_method_calls_in_expr(stmt.init, calls)
    elif isinstance(stmt, AssignmentStmt):
        _collect_method_calls_in_expr(stmt.target, calls)
        _collect_method_calls_in_expr(stmt.value, calls)
    elif isinstance(stmt, IfStmt):
        _collect_method_calls_in_expr(stmt.condition, calls)
        _collect_method_calls(stmt.then, calls)
        _collect_method_calls(stmt.else_, calls)
    elif isinstance(stmt, ForStmt):
        _collect_method_calls_in_expr(stmt.condition, calls)
        _collect_method_calls(stmt.body, calls)
    elif isinstance(stmt, ReturnStmt):
        if stmt.value is not None:
            _collect_method_calls_in_expr(stmt.value, calls)


def _collect_method_calls_in_expr(expr: Expression | None, calls: set[str]) -> None:
    if expr is None:
        return
    if isinstance(expr, CallExpr):
        if isinstance(expr.callee, PropertyAccessExpr):
            calls.add(expr.callee.property)
        if isinstance(expr.callee, MemberExpr):
            if isinstance(expr.callee.object, Identifier) and expr.callee.object.name == "this":
                calls.add(expr.callee.property)
        _collect_method_calls_in_expr(expr.callee, calls)
        for arg in expr.args:
            _collect_method_calls_in_expr(arg, calls)
    elif isinstance(expr, BinaryExpr):
        _collect_method_calls_in_expr(expr.left, calls)
        _collect_method_calls_in_expr(expr.right, calls)
    elif isinstance(expr, UnaryExpr):
        _collect_method_calls_in_expr(expr.operand, calls)
    elif isinstance(expr, MemberExpr):
        _collect_method_calls_in_expr(expr.object, calls)
    elif isinstance(expr, TernaryExpr):
        _collect_method_calls_in_expr(expr.condition, calls)
        _collect_method_calls_in_expr(expr.consequent, calls)
        _collect_method_calls_in_expr(expr.alternate, calls)
    elif isinstance(expr, IndexAccessExpr):
        _collect_method_calls_in_expr(expr.object, calls)
        _collect_method_calls_in_expr(expr.index, calls)
    elif isinstance(expr, IncrementExpr):
        _collect_method_calls_in_expr(expr.operand, calls)
    elif isinstance(expr, DecrementExpr):
        _collect_method_calls_in_expr(expr.operand, calls)


def _has_cycle(
    name: str,
    call_graph: dict[str, set[str]],
    method_names: set[str],
    visited: set[str],
    stack: set[str],
) -> bool:
    if name in stack:
        return True
    if name in visited:
        return False
    visited.add(name)
    stack.add(name)

    for callee in call_graph.get(name, set()):
        if callee in method_names:
            if _has_cycle(callee, call_graph, method_names, visited, stack):
                return True

    stack.discard(name)
    return False
