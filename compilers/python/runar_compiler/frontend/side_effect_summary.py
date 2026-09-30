"""Side-effect summary pass.

Mirrors ``packages/runar-compiler/src/passes/side-effect-summary.ts``.

Classifies each method on a ContractNode by the side effects it has on
the contract's continuation requirements. Walks the private-method
call graph so effects buried inside private helpers surface to their
public callers.

Also consumed by ``typecheck.py``'s requireOutputP2PKH output-layout
guards (Crit-3, R-300, index-0 continuation collision) — F-075: those
guards must see the same effects the continuation is injected from.

Consumed by ``anf_lower.py`` for:

  - Auto-injecting continuation parameters (``_changePKH``,
    ``_changeAmount``, ``_newAmount``, ``txPreimage``) on public
    stateful methods.
  - Gating emission of the hashOutputs continuation assertion.
  - Deciding whether a private-helper call should be inlined into the
    caller's binding stream so its add_output / add_data_output ANF
    nodes register on the caller's continuation hash.

Recursion across private methods is forbidden by the language
validator, so the call-graph walk terminates.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ast_nodes import (
    ArrayLiteralExpr,
    AssignmentStmt,
    BigIntLiteral,
    BinaryExpr,
    CallExpr,
    ContractNode,
    DecrementExpr,
    ExpressionStmt,
    ForStmt,
    Identifier,
    IfStmt,
    IncrementExpr,
    IndexAccessExpr,
    MemberExpr,
    MethodNode,
    PropertyAccessExpr,
    ReturnStmt,
    Statement,
    TernaryExpr,
    UnaryExpr,
    VariableDeclStmt,
)


_STATE_OUTPUT_INTRINSICS = {"addOutput", "addRawOutput"}
_DATA_OUTPUT_INTRINSICS = {"addDataOutput"}


@dataclass
class MethodEffects:
    """Effects a method has on the contract's continuation. Each flag
    is True if the effect occurs anywhere reachable from the method
    body, including transitively via private-method calls."""

    mutates_state: bool = False
    has_state_output: bool = False
    has_data_output: bool = False
    uses_preimage: bool = False
    # Calls requireOutputP2PKH(...) with any output index.
    calls_require_output_p2pkh: bool = False
    # Calls requireOutputP2PKH(0, ...) (literal index 0).
    requires_output_p2pkh_zero: bool = False

    def union(self, other: "MethodEffects") -> None:
        self.mutates_state = self.mutates_state or other.mutates_state
        self.has_state_output = self.has_state_output or other.has_state_output
        self.has_data_output = self.has_data_output or other.has_data_output
        self.uses_preimage = self.uses_preimage or other.uses_preimage
        self.calls_require_output_p2pkh = (
            self.calls_require_output_p2pkh or other.calls_require_output_p2pkh
        )
        self.requires_output_p2pkh_zero = (
            self.requires_output_p2pkh_zero or other.requires_output_p2pkh_zero
        )


@dataclass
class ContinuationShape:
    """Continuation requirements derived from MethodEffects."""

    needs_change: bool
    needs_new_amount: bool
    is_terminal: bool


def continuation_shape_for(eff: MethodEffects) -> ContinuationShape:
    needs_change = (
        eff.mutates_state or eff.has_state_output or eff.has_data_output
    )
    # addOutput / addRawOutput already specify per-output amounts, so
    # when those are present the single-output _newAmount is redundant.
    # Otherwise the single-output continuation path needs _newAmount to
    # size the new state UTXO.
    needs_new_amount = (
        (eff.mutates_state or eff.has_data_output) and not eff.has_state_output
    )
    return ContinuationShape(
        needs_change=needs_change,
        needs_new_amount=needs_new_amount,
        is_terminal=not needs_change,
    )


def compute_side_effect_summary(contract: ContractNode) -> dict[str, MethodEffects]:
    """Classify every method on the contract.

    On-demand DFS with memoization. Returns a dict keyed by method name
    (constructor included under the key ``"constructor"``).
    """

    summary: dict[str, MethodEffects] = {}
    mutable_props: set[str] = {p.name for p in contract.properties if not p.readonly}
    private_by_name: dict[str, MethodNode] = {
        m.name: m
        for m in contract.methods
        if m.visibility != "public"
    }
    in_progress: set[str] = set()

    def classify(method_name: str, body: list[Statement]) -> MethodEffects:
        if method_name in summary:
            return summary[method_name]
        if method_name in in_progress:
            # Validation should reject recursion before we get here;
            # return empty effects defensively to avoid infinite loops.
            return MethodEffects()
        in_progress.add(method_name)
        effects = MethodEffects()
        for stmt in body:
            _collect_stmt(stmt, effects, mutable_props, private_by_name, classify)
        in_progress.discard(method_name)
        summary[method_name] = effects
        return effects

    classify("constructor", contract.constructor.body)
    for m in contract.methods:
        classify(m.name, m.body)
    return summary


def _collect_stmt(
    stmt: Statement,
    into: MethodEffects,
    mutable_props: set[str],
    private_by_name: dict[str, MethodNode],
    classify,
) -> None:
    if isinstance(stmt, AssignmentStmt):
        if isinstance(stmt.target, PropertyAccessExpr):
            if stmt.target.property in mutable_props:
                into.mutates_state = True
        # Issue #123 F3: both sides may still contain calls (output intrinsics
        # could hide in the target's index/object as well as the value).
        if stmt.target is not None:
            _collect_expr(stmt.target, into, mutable_props, private_by_name, classify)
        if stmt.value is not None:
            _collect_expr(stmt.value, into, mutable_props, private_by_name, classify)
        return
    if isinstance(stmt, ExpressionStmt):
        if stmt.expr is not None:
            _collect_expr(stmt.expr, into, mutable_props, private_by_name, classify)
        return
    if isinstance(stmt, IfStmt):
        if stmt.condition is not None:
            _collect_expr(stmt.condition, into, mutable_props, private_by_name, classify)
        for inner in stmt.then:
            _collect_stmt(inner, into, mutable_props, private_by_name, classify)
        for inner in stmt.else_:
            _collect_stmt(inner, into, mutable_props, private_by_name, classify)
        return
    if isinstance(stmt, ForStmt):
        # Issue #123 F3: walk the full loop header — an output intrinsic can hide
        # in init or condition, not only in update/body.
        if stmt.init is not None:
            _collect_stmt(stmt.init, into, mutable_props, private_by_name, classify)
        if stmt.condition is not None:
            _collect_expr(stmt.condition, into, mutable_props, private_by_name, classify)
        if stmt.update is not None:
            _collect_stmt(stmt.update, into, mutable_props, private_by_name, classify)
        for inner in stmt.body:
            _collect_stmt(inner, into, mutable_props, private_by_name, classify)
        return
    if isinstance(stmt, ReturnStmt):
        if stmt.value is not None:
            _collect_expr(stmt.value, into, mutable_props, private_by_name, classify)
        return
    if isinstance(stmt, VariableDeclStmt):
        if stmt.init is not None:
            _collect_expr(stmt.init, into, mutable_props, private_by_name, classify)
        return


def _collect_expr(
    expr,
    into: MethodEffects,
    mutable_props: set[str],
    private_by_name: dict[str, MethodNode],
    classify,
) -> None:
    if expr is None:
        return
    if isinstance(expr, (IncrementExpr, DecrementExpr)):
        if isinstance(expr.operand, PropertyAccessExpr):
            if expr.operand.property in mutable_props:
                into.mutates_state = True
        return
    if isinstance(expr, CallExpr):
        callee = expr.callee
        callee_name: str | None = None
        if isinstance(callee, PropertyAccessExpr):
            callee_name = callee.property
        elif isinstance(callee, MemberExpr):
            callee_name = callee.property

        if callee_name is not None:
            if callee_name in _STATE_OUTPUT_INTRINSICS:
                into.has_state_output = True
            if callee_name in _DATA_OUTPUT_INTRINSICS:
                into.has_data_output = True
            target = private_by_name.get(callee_name)
            if target is not None:
                into.union(classify(target.name, target.body))

        if isinstance(callee, Identifier):
            if callee.name == "checkPreimage":
                into.uses_preimage = True
            if callee.name == "requireOutputP2PKH":
                into.calls_require_output_p2pkh = True
                if expr.args:
                    idx = expr.args[0]
                    if isinstance(idx, BigIntLiteral) and idx.value == 0:
                        into.requires_output_p2pkh_zero = True
            target = private_by_name.get(callee.name)
            if target is not None:
                into.union(classify(target.name, target.body))

        for arg in expr.args:
            _collect_expr(arg, into, mutable_props, private_by_name, classify)
        if not isinstance(callee, Identifier):
            _collect_expr(callee, into, mutable_props, private_by_name, classify)
        return
    if isinstance(expr, BinaryExpr):
        _collect_expr(expr.left, into, mutable_props, private_by_name, classify)
        _collect_expr(expr.right, into, mutable_props, private_by_name, classify)
        return
    if isinstance(expr, UnaryExpr):
        _collect_expr(expr.operand, into, mutable_props, private_by_name, classify)
        return
    if isinstance(expr, TernaryExpr):
        _collect_expr(expr.condition, into, mutable_props, private_by_name, classify)
        _collect_expr(expr.consequent, into, mutable_props, private_by_name, classify)
        _collect_expr(expr.alternate, into, mutable_props, private_by_name, classify)
        return
    if isinstance(expr, IndexAccessExpr):
        _collect_expr(expr.object, into, mutable_props, private_by_name, classify)
        _collect_expr(expr.index, into, mutable_props, private_by_name, classify)
        return
    if isinstance(expr, MemberExpr):
        _collect_expr(expr.object, into, mutable_props, private_by_name, classify)
        return
    if isinstance(expr, ArrayLiteralExpr):
        for el in expr.elements:
            _collect_expr(el, into, mutable_props, private_by_name, classify)
        return


