"""D25 -- bind every state continuation to the input that made it.

SECURITY CORE (fund safety). Mirrors
``packages/runar-compiler/src/passes/continuation-binding.ts`` (the TypeScript
reference): same classification, same hidden field name, same diagnostics.

Before D25 every stateful covenant checked ``hash256(continuation || change)
== hashOutputs`` over the WHOLE output list, and the BIP-143 preimage carries
no input position, so two UTXOs of one contract spent in one transaction that
reach the same post-state were BOTH satisfied by ONE continuation output.

The binding is a property of the CONTRACT, classified once:

* ``'single'``   every continuation-producing public method is mutate-only
  and reads nothing SINGLE zeroes or redefines: those methods default to
  SIGHASH_SINGLE|FORKID (ALL|ANYONECANPAY|FORKID becomes
  SINGLE|ANYONECANPAY|FORKID); an explicit ``@sighash ALL|FORKID`` is refused.
* ``'bind'``     at least one auto-continuation method, but not ``'single'``:
  a hidden last state field ``_spentOutpointHash =
  sha256(extractOutpoint(txPreimage))`` is written by every continuation.
* ``'explicit'`` every continuation method sizes its own outputs: unchanged
  bytes, a warning on an unsigned ``addOutput(extractAmount(...))``.
* ``'none'``     stateless, or no public method produces a continuation.
"""

from __future__ import annotations

import dataclasses

from runar_compiler.frontend.ast_nodes import (
    ArrayLiteralExpr,
    AssignmentStmt,
    BinaryExpr,
    ByteStringLiteral,
    CallExpr,
    ContractNode,
    ExpressionStmt,
    ForStmt,
    Identifier,
    IfStmt,
    IndexAccessExpr,
    MemberExpr,
    MethodNode,
    PrimitiveType,
    PropertyAccessExpr,
    PropertyNode,
    ReturnStmt,
    SourceLocation,
    TernaryExpr,
    UnaryExpr,
    VariableDeclStmt,
)
from runar_compiler.frontend.diagnostic import Diagnostic, Severity
from runar_compiler.frontend.side_effect_summary import (
    compute_side_effect_summary,
    continuation_shape_for,
)
from runar_compiler.frontend.sighash_directive import (
    BASE_ALL,
    BASE_SINGLE,
    BASE_TYPE_MASK,
    FLAG_ANYONECANPAY,
    FLAG_FORKID,
)

# The hidden state field of a 'bind' contract (reserved; last mutable property).
TWIN_BINDING_FIELD = "_spentOutpointHash"

# SIGHASH_SINGLE|FORKID.
SIGHASH_SINGLE_FORKID = BASE_SINGLE | FLAG_FORKID

# Builtins whose meaning SINGLE zeroes or redefines (a mutate-only method
# reading one keeps ALL).
_SINGLE_INCOMPATIBLE_READS = frozenset({
    "extractHashSequence",
    "extractOutputHash",
    "extractOutputs",
    "extractSigHashType",
    "requireOutputP2PKH",
})


def explicit_all_sibling_message(method: str) -> str:
    """D25: the shared error text for an explicit ALL sibling in a 'single' contract."""
    return (
        f"method '{method}': @sighash ALL|FORKID on a state-continuation method of a contract whose "
        f"continuation methods are all mutate-only reopens twin-input theft: such a contract commits each "
        f"continuation under SIGHASH_SINGLE (one output per input), and one ALL method lets its input reuse "
        f"a sibling's output while its own value leaves as change. Remove the directive (the default is "
        f"SINGLE|FORKID) or write @sighash SINGLE|FORKID"
    )


def unsigned_add_output_message(method: str) -> str:
    """D25: the shared warning text for an unsigned value-conserving addOutput (D12 C1)."""
    return (
        f"method '{method}' re-creates the contract with addOutput(extractAmount(...), ...) and checks no "
        f"signature: two UTXOs of this contract spent in one transaction that reach the same state are both "
        f"satisfied by ONE such output, and the other input's value leaves as anyone's change (twin-input "
        f"aliasing). A method that sizes its own outputs is not bound to its input; require a signature, or "
        f"let the compiler size the continuation (write state instead of calling addOutput)"
    )


def _callee_name(callee) -> str | None:
    if isinstance(callee, Identifier):
        return callee.name
    if isinstance(callee, (PropertyAccessExpr, MemberExpr)):
        return callee.property
    return None


def _reachable_calls(body: list, privates: dict[str, MethodNode]) -> set[str]:
    """Every call name reachable from ``body``, through private helpers (cycle-guarded)."""
    names: set[str] = set()
    visiting: set[str] = set()

    def stmts(ss) -> None:
        for s in ss or []:
            stmt(s)

    def stmt(s) -> None:
        if s is None:
            return
        if isinstance(s, AssignmentStmt):
            expr(s.target)
            expr(s.value)
        elif isinstance(s, ExpressionStmt):
            expr(s.expr)
        elif isinstance(s, IfStmt):
            expr(s.condition)
            stmts(s.then)
            stmts(s.else_)
        elif isinstance(s, ForStmt):
            stmt(s.init)
            expr(s.condition)
            stmt(s.update)
            stmts(s.body)
        elif isinstance(s, ReturnStmt):
            expr(s.value)
        elif isinstance(s, VariableDeclStmt):
            expr(s.init)

    def expr(e) -> None:
        if e is None:
            return
        if isinstance(e, CallExpr):
            n = _callee_name(e.callee)
            if n is not None:
                names.add(n)
                t = privates.get(n)
                if t is not None and n not in visiting:
                    visiting.add(n)
                    stmts(t.body)
                    visiting.discard(n)
            for a in e.args:
                expr(a)
            if not isinstance(e.callee, Identifier):
                expr(e.callee)
        elif isinstance(e, BinaryExpr):
            expr(e.left)
            expr(e.right)
        elif isinstance(e, UnaryExpr):
            expr(e.operand)
        elif isinstance(e, TernaryExpr):
            expr(e.condition)
            expr(e.consequent)
            expr(e.alternate)
        elif isinstance(e, IndexAccessExpr):
            expr(e.object)
            expr(e.index)
        elif isinstance(e, MemberExpr):
            expr(e.object)
        elif isinstance(e, ArrayLiteralExpr):
            for x in e.elements:
                expr(x)

    stmts(body)
    return names


def _privates_of(contract: ContractNode) -> dict[str, MethodNode]:
    return {m.name: m for m in contract.methods if m.visibility == "private"}


def _classify(contract: ContractNode) -> tuple[str, list[MethodNode]]:
    if contract.parent_class != "StatefulSmartContract":
        return "none", []
    effects = compute_side_effect_summary(contract)
    privates = _privates_of(contract)
    continuation_methods: list[MethodNode] = []
    any_auto = False
    all_single_eligible = True
    for m in contract.methods:
        if m.visibility != "public":
            continue
        e = effects.get(m.name)
        if e is None or not continuation_shape_for(e).needs_change:
            continue
        continuation_methods.append(m)
        if not e.has_state_output:
            any_auto = True
        mode = m.sighash_type
        base = BASE_ALL if mode is None else mode & BASE_TYPE_MASK
        mode_ok = base in (BASE_ALL, BASE_SINGLE)
        reads = _reachable_calls(m.body, privates)
        reads_ok = not any(n in _SINGLE_INCOMPATIBLE_READS for n in reads)
        if e.has_state_output or e.has_data_output or not mode_ok or not reads_ok:
            all_single_eligible = False
    if not continuation_methods:
        return "none", continuation_methods
    if not any_auto:
        return "explicit", continuation_methods
    return ("single" if all_single_eligible else "bind"), continuation_methods


def continuation_class(contract: ContractNode) -> str:
    """The contract's D25 class: 'none' | 'single' | 'bind' | 'explicit'."""
    return _classify(contract)[0]


def resolve_continuation_binding(contract: ContractNode) -> list[Diagnostic]:
    """D25 resolution, run by the validator right before the @sighash checks.

    In a 'single' contract it sets each continuation method's ``sighash_type``
    and refuses an explicit pure-ALL directive; in an 'explicit' contract it
    warns about unsigned value-conserving addOutput methods. Idempotent.
    """
    diags: list[Diagnostic] = []
    cls, continuation_methods = _classify(contract)
    if cls == "single":
        for m in continuation_methods:
            mode = m.sighash_type
            if mode is None:
                m.sighash_type = SIGHASH_SINGLE_FORKID
            elif (mode & BASE_TYPE_MASK) == BASE_ALL:
                if (mode & FLAG_ANYONECANPAY) != 0:
                    m.sighash_type = (mode & ~BASE_TYPE_MASK) | BASE_SINGLE
                else:
                    diags.append(Diagnostic(
                        message=explicit_all_sibling_message(m.name),
                        severity=Severity.ERROR,
                        loc=m.source_location,
                    ))
    elif cls == "explicit":
        privates = _privates_of(contract)
        for m in continuation_methods:
            mode = m.sighash_type
            if mode is not None and (mode & BASE_TYPE_MASK) != BASE_ALL:
                continue
            if _unsigned_value_conserving_add_output(m, privates):
                # The Python AST carries no call-site location, so the
                # warning points at the method (TS points at the addOutput).
                diags.append(Diagnostic(
                    message=unsigned_add_output_message(m.name),
                    severity=Severity.WARNING,
                    loc=m.source_location,
                ))
    return diags


def _is_signature_check(name: str) -> bool:
    return name in ("checkSig", "checkMultiSig") or name.startswith("verify")


def _unsigned_value_conserving_add_output(method: MethodNode, privates: dict[str, MethodNode]) -> bool:
    """D12 C1: an ``addOutput`` whose satoshis argument reads ``extractAmount``
    (directly, or through a local initialised from it) in a method that
    verifies no signature."""
    calls = _reachable_calls(method.body, privates)
    if any(_is_signature_check(n) for n in calls):
        return False
    amount_locals: set[str] = set()

    def reads_amount(e) -> bool:
        if isinstance(e, CallExpr):
            return _callee_name(e.callee) == "extractAmount" or any(reads_amount(a) for a in e.args)
        if isinstance(e, Identifier):
            return e.name in amount_locals
        if isinstance(e, BinaryExpr):
            return reads_amount(e.left) or reads_amount(e.right)
        if isinstance(e, UnaryExpr):
            return reads_amount(e.operand)
        if isinstance(e, TernaryExpr):
            return reads_amount(e.condition) or reads_amount(e.consequent) or reads_amount(e.alternate)
        return False

    found = [False]
    visiting: set[str] = set()

    def stmts(ss) -> None:
        for s in ss or []:
            stmt(s)

    def stmt(s) -> None:
        if isinstance(s, VariableDeclStmt):
            if s.init is not None and reads_amount(s.init):
                amount_locals.add(s.name)
            expr(s.init)
        elif isinstance(s, AssignmentStmt):
            expr(s.value)
        elif isinstance(s, ExpressionStmt):
            expr(s.expr)
        elif isinstance(s, IfStmt):
            expr(s.condition)
            stmts(s.then)
            stmts(s.else_)
        elif isinstance(s, ForStmt):
            stmts(s.body)
        elif isinstance(s, ReturnStmt):
            expr(s.value)

    def expr(e) -> None:
        if not isinstance(e, CallExpr):
            return
        n = _callee_name(e.callee)
        if n == "addOutput" and e.args and reads_amount(e.args[0]):
            found[0] = True
        t = privates.get(n) if n is not None else None
        if t is not None and t.name not in visiting:
            visiting.add(t.name)
            stmts(t.body)
            visiting.discard(t.name)
        for a in e.args:
            expr(a)

    stmts(method.body)
    return found[0]


def inject_continuation_binding(contract: ContractNode) -> ContractNode:
    """D25 injection, run after typecheck (before fixed-array expansion): a
    'bind' contract gains the hidden ``_spentOutpointHash: Sha256 = 0x00..00``
    as its LAST property. ANF lowering then writes it in every
    auto-continuation and appends it to every addOutput. The zero initializer
    keeps it out of the constructor ABI. Any other class is returned
    unchanged."""
    if continuation_class(contract) != "bind":
        return contract
    if any(p.name == TWIN_BINDING_FIELD for p in contract.properties):
        return contract
    loc = contract.constructor.source_location
    field = PropertyNode(
        name=TWIN_BINDING_FIELD,
        type=PrimitiveType(name="Sha256"),
        readonly=False,
        initializer=ByteStringLiteral(value="00" * 32),
        source_location=loc if loc is not None else SourceLocation(),
    )
    return dataclasses.replace(contract, properties=[*contract.properties, field])
