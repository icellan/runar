"""Field-usage validation for per-method ``@sighash`` modes (issue #123).

SECURITY CORE. A relaxed sighash flag ZEROES specific BIP-143 preimage fields; a
covenant that still reads one of those fields (or binds an output the flag no
longer commits to) is exploitable — the attacker gets a free hand over exactly
the part of the transaction the covenant believed it had pinned. This pass
rejects, at compile time, every field read / output binding that becomes unsound
under the method's declared mode.

BIP-143 field availability by sighash type (present = signed, ZEROED otherwise):

    field                 ALL    NONE   SINGLE   +ANYONECANPAY
    ---------------------------------------------------------
    hashPrevouts           ok     ok     ok        ZEROED (all-inputs digest)
    hashSequence           ok     ZERO   ZERO      ZEROED (all-inputs digest)
    outpoint (this input)  ok     ok     ok        ok
    scriptCode             ok     ok     ok        ok
    amount (this input)    ok     ok     ok        ok
    hashOutputs            ok     ZERO   same-idx   (per base)

Port of packages/runar-compiler/src/passes/sighash-validate.ts (incl. the F1/F3/
F4 security-audit fixes from e88f202c).
"""

from __future__ import annotations

from runar_compiler.frontend.ast_nodes import (
    ContractNode,
    MethodNode,
    AssignmentStmt,
    ExpressionStmt,
    IfStmt,
    ForStmt,
    ReturnStmt,
    VariableDeclStmt,
    CallExpr,
    BinaryExpr,
    UnaryExpr,
    TernaryExpr,
    IndexAccessExpr,
    MemberExpr,
    PropertyAccessExpr,
    ArrayLiteralExpr,
    Identifier,
)
from runar_compiler.frontend.diagnostic import Diagnostic, Severity
from runar_compiler.frontend.side_effect_summary import (
    compute_side_effect_summary,
    continuation_shape_for,
)
from runar_compiler.frontend.sighash_directive import (
    BASE_TYPE_MASK,
    BASE_ALL,
    BASE_NONE,
    BASE_SINGLE,
    FLAG_ANYONECANPAY,
    describe_sighash,
)

# Builtins that read the all-inputs prevouts digest (zeroed under ANYONECANPAY).
_HASHPREVOUTS_READERS = frozenset({"extractHashPrevouts"})
# Builtins that read the all-inputs sequence digest (zeroed unless pure ALL).
_HASHSEQUENCE_READERS = frozenset({"extractHashSequence"})
# Builtins that read the outputs digest (zeroed under NONE).
_HASHOUTPUTS_READERS = frozenset({"extractOutputHash", "extractOutputs"})
# Intrinsic that binds a companion input's prevout script (needs hashPrevouts).
_PREVOUT_SCRIPT_INTRINSICS = frozenset({"extractPrevOutputScript"})
# Intrinsics that assert an output (bound via hashOutputs).
_OUTPUT_ASSERT_INTRINSICS = frozenset({"requireOutputP2PKH"})
# Output-emitting intrinsics (state continuation outputs).
_STATE_OUTPUT_INTRINSICS = frozenset({"addOutput", "addRawOutput"})
_DATA_OUTPUT_INTRINSICS = frozenset({"addDataOutput"})


class _Usage:
    __slots__ = ("name", "loc")

    def __init__(self, name: str, loc=None):
        self.name = name
        self.loc = loc


class _MethodScan:
    __slots__ = (
        "hash_prevouts_reads",
        "hash_sequence_reads",
        "hash_outputs_reads",
        "prevout_script_reads",
        "output_asserts",
        "state_output_count",
        "data_output_count",
    )

    def __init__(self):
        self.hash_prevouts_reads: list[_Usage] = []
        self.hash_sequence_reads: list[_Usage] = []
        self.hash_outputs_reads: list[_Usage] = []
        self.prevout_script_reads: list[_Usage] = []
        self.output_asserts: list[_Usage] = []
        self.state_output_count = 0
        self.data_output_count = 0


def validate_sighash_usage(contract: ContractNode) -> list[Diagnostic]:
    """Validate every public method's ``@sighash`` field usage. Returns
    diagnostics (errors and warnings). Methods with no directive (default
    ALL|FORKID) are never flagged.
    """
    diagnostics: list[Diagnostic] = []
    is_stateful = contract.parent_class == "StatefulSmartContract"
    side_effects = compute_side_effect_summary(contract)

    private_by_name: dict[str, MethodNode] = {
        m.name: m for m in contract.methods if m.visibility == "private"
    }

    for method in contract.methods:
        if method.visibility != "public":
            continue
        if method.sighash_type is None:  # default ALL|FORKID — allow all
            continue

        mode = method.sighash_type
        base = mode & BASE_TYPE_MASK
        acp = (mode & FLAG_ANYONECANPAY) != 0
        label = describe_sighash(mode)

        scan = _scan_method(method, private_by_name)

        # state-continuation binding (stateful auto-injected hashOutputs)
        eff = side_effects.get(method.name)
        needs_continuation = (
            is_stateful and eff is not None and continuation_shape_for(eff).needs_change
        )

        def push(u: _Usage, msg: str) -> None:
            diagnostics.append(Diagnostic(
                message=msg, severity=Severity.ERROR,
                loc=u.loc if u.loc is not None else method.source_location,
            ))

        def push_warn(u: _Usage, msg: str) -> None:
            diagnostics.append(Diagnostic(
                message=msg, severity=Severity.WARNING,
                loc=u.loc if u.loc is not None else method.source_location,
            ))

        # ---- ANYONECANPAY: only THIS input is signed ----------------------
        if acp:
            for u in scan.hash_prevouts_reads:
                push(u, f"@sighash {label}: '{u.name}' reads hashPrevouts, which is zeroed under ANYONECANPAY (only this input is signed) — the covenant cannot constrain the input set, so any check on it is trivially bypassable. Remove ANYONECANPAY or drop the {u.name} read.")
            for u in scan.prevout_script_reads:
                push(u, f"@sighash {label}: '{u.name}' binds a companion input's prevout script, but ANYONECANPAY zeroes hashPrevouts so the input set is unconstrained — an attacker can substitute inputs freely. Companion-input covenants require the full prevout set to be committed (drop ANYONECANPAY).")

        # ---- hashSequence is committed only under pure ALL (no ACP) -------
        hash_sequence_sound = base == BASE_ALL and not acp
        if not hash_sequence_sound:
            for u in scan.hash_sequence_reads:
                push(u, f"@sighash {label}: '{u.name}' reads hashSequence, which is zeroed under any mode other than SIGHASH_ALL (NONE / SINGLE / ANYONECANPAY all clear it) — the read yields attacker-chosen zeros. Use SIGHASH_ALL or drop the {u.name} read.")

        # ---- NONE commits to NO outputs -----------------------------------
        if base == BASE_NONE:
            if needs_continuation:
                push(_Usage("state continuation", method.source_location),
                     f"@sighash {label}: this stateful method binds a state-continuation output via hashOutputs, but NONE commits to NO outputs (hashOutputs is zeroed) — the continuation is unenforceable, so the next-state covenant is meaningless and the spend is unsound. A continuation covenant cannot use NONE.")
            for u in scan.hash_outputs_reads:
                push(u, f"@sighash {label}: '{u.name}' reads hashOutputs, which is zeroed under NONE — the read yields attacker-chosen zeros. Drop the output read or use ALL/SINGLE.")
            for u in scan.output_asserts:
                push(u, f"@sighash {label}: '{u.name}' asserts an output, but NONE commits to no outputs — the assertion cannot be enforced. Use ALL/SINGLE.")
            if scan.state_output_count + scan.data_output_count > 0:
                total = scan.state_output_count + scan.data_output_count
                push(_Usage("addOutput", method.source_location),
                     f"@sighash {label}: this method emits {total} output(s) (addOutput/addRawOutput/addDataOutput), but NONE commits to no outputs — those outputs are unenforceable. Use ALL/SINGLE.")

        # ---- SINGLE commits ONLY to the same-index output -----------------
        if base == BASE_SINGLE:
            # A fixed-index output assertion (requireOutputP2PKH) cannot be proven
            # to land at THIS input's index, the only output SINGLE commits to.
            for u in scan.output_asserts:
                push(u, f"@sighash {label}: '{u.name}' asserts an output at a fixed index, but SINGLE commits ONLY to the output at THIS input's index — the asserted index cannot be statically proven equal to the input index, so the assertion may bind an uncommitted (attacker-controllable) output or silently brick the spend. Use ALL.")

            # D25: a mutate-only (auto-continuation) method under SINGLE is SOUND
            # and is the DEFAULT for a contract whose continuation methods are all
            # mutate-only (continuation_binding.py). SINGLE hashes the whole
            # same-index output, value included, and the F-024 floor
            # (``_newAmount >= extractAmount``) stops a dust continuation; the
            # change is not committed (N-038). The refusal that used to stand here
            # (e88f202c8) predates both.
            is_mutate_only_auto_continuation = (
                needs_continuation
                and scan.state_output_count == 0
                and scan.data_output_count == 0
            )

            # Committed-output count for the multi-output rule: explicit state
            # outputs (addOutput) OR the single auto-continuation, plus any data
            # outputs. The change output is conditional (0 under an exact-cover
            # call) and is NOT counted.
            if scan.state_output_count > 0:
                state_outputs = scan.state_output_count
            elif needs_continuation:
                state_outputs = 1
            else:
                state_outputs = 0
            committed = state_outputs + scan.data_output_count

            if is_mutate_only_auto_continuation:
                pass  # Sound (see above): nothing to report.
            elif committed > 1:
                extra = " + state continuation" if state_outputs > scan.state_output_count else ""
                push(_Usage("multi-output continuation", method.source_location),
                     f"@sighash {label}: SINGLE commits ONLY to the output at this input's index, but this method binds {committed} outputs ({scan.state_output_count} addOutput + {scan.data_output_count} addDataOutput{extra}). Outputs beyond the same-index one are uncommitted and attacker-controllable. A SINGLE covenant must bind exactly one same-index output.")
            elif committed == 1:
                # Legitimate pairwise input->output covenant: exactly one explicit
                # addOutput/addRawOutput (or single data output). The same-index
                # output IS committed, but SINGLE does not let the compiler prove
                # statically that its VALUE equals the full protected amount — a
                # runtime obligation on the caller. Allow, but warn.
                push_warn(_Usage("single-output SINGLE covenant", method.source_location),
                          f"@sighash {label}: SINGLE commits ONLY to the output at this input's index. This method binds exactly one output there, which is sound ONLY if that output carries the FULL protected value — SINGLE does not pin the amount, so a short-changed same-index output cannot be caught at compile time. Ensure the caller places the fully-valued output at this input's index.")

            # hashSequence reads under SINGLE are already reported by the shared
            # hashSequence rule above (no double report).

    return diagnostics


def _scan_method(method: MethodNode, private_by_name: dict[str, MethodNode]) -> _MethodScan:
    """Walk a method body (transitively through private-method calls) collecting
    every flagged builtin/intrinsic usage. Cycle-guarded.
    """
    scan = _MethodScan()
    visiting: set[str] = set()

    def walk_body(stmts) -> None:
        for s in stmts:
            walk_stmt(s)

    def walk_stmt(stmt) -> None:
        if isinstance(stmt, AssignmentStmt):
            # Walk BOTH sides: a forbidden field read can hide in the assignment
            # target (e.g. ``arr[extractOutputHash(pre)] = x``), not just value.
            if stmt.target is not None:
                walk_expr(stmt.target)
            if stmt.value is not None:
                walk_expr(stmt.value)
            return
        if isinstance(stmt, ExpressionStmt):
            if stmt.expr is not None:
                walk_expr(stmt.expr)
            return
        if isinstance(stmt, IfStmt):
            if stmt.condition is not None:
                walk_expr(stmt.condition)
            walk_body(stmt.then)
            if stmt.else_:
                walk_body(stmt.else_)
            return
        if isinstance(stmt, ForStmt):
            # Walk the full loop header: init and condition can hide a forbidden
            # field read just as easily as the body/update do.
            if stmt.init is not None:
                walk_stmt(stmt.init)
            if stmt.condition is not None:
                walk_expr(stmt.condition)
            if stmt.update is not None:
                walk_stmt(stmt.update)
            walk_body(stmt.body)
            return
        if isinstance(stmt, ReturnStmt):
            if stmt.value is not None:
                walk_expr(stmt.value)
            return
        if isinstance(stmt, VariableDeclStmt):
            if stmt.init is not None:
                walk_expr(stmt.init)
            return

    def callee_name(callee) -> str | None:
        if isinstance(callee, Identifier):
            return callee.name
        if isinstance(callee, (PropertyAccessExpr, MemberExpr)):
            return callee.property
        return None

    def walk_expr(expr) -> None:
        if expr is None:
            return
        if isinstance(expr, CallExpr):
            name = callee_name(expr.callee)
            loc = None  # CallExpr carries no source location in this tier
            if name is not None:
                if name in _HASHPREVOUTS_READERS:
                    scan.hash_prevouts_reads.append(_Usage(name, loc))
                if name in _HASHSEQUENCE_READERS:
                    scan.hash_sequence_reads.append(_Usage(name, loc))
                if name in _HASHOUTPUTS_READERS:
                    scan.hash_outputs_reads.append(_Usage(name, loc))
                if name in _PREVOUT_SCRIPT_INTRINSICS:
                    scan.prevout_script_reads.append(_Usage(name, loc))
                if name in _OUTPUT_ASSERT_INTRINSICS:
                    scan.output_asserts.append(_Usage(name, loc))
                if name in _STATE_OUTPUT_INTRINSICS:
                    scan.state_output_count += 1
                if name in _DATA_OUTPUT_INTRINSICS:
                    scan.data_output_count += 1
                # Recurse into a private helper so its usages surface to caller.
                target = private_by_name.get(name)
                if target is not None and name not in visiting:
                    visiting.add(name)
                    walk_body(target.body)
                    visiting.discard(name)
            for a in expr.args:
                walk_expr(a)
            if not isinstance(expr.callee, Identifier):
                walk_expr(expr.callee)
            return
        if isinstance(expr, BinaryExpr):
            walk_expr(expr.left)
            walk_expr(expr.right)
            return
        if isinstance(expr, UnaryExpr):
            walk_expr(expr.operand)
            return
        if isinstance(expr, TernaryExpr):
            walk_expr(expr.condition)
            walk_expr(expr.consequent)
            walk_expr(expr.alternate)
            return
        if isinstance(expr, IndexAccessExpr):
            walk_expr(expr.object)
            walk_expr(expr.index)
            return
        if isinstance(expr, MemberExpr):
            walk_expr(expr.object)
            return
        if isinstance(expr, PropertyAccessExpr):
            return
        if isinstance(expr, ArrayLiteralExpr):
            for el in expr.elements:
                walk_expr(el)
            return

    walk_body(method.body)
    return scan
