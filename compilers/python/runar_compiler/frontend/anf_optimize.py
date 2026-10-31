"""ANF-level EC (elliptic curve) optimizer -- Pass 4.5.

Applies algebraic simplification rules to EC intrinsic calls in the ANF IR,
mirroring the TypeScript implementation in
``packages/runar-compiler/src/optimizer/ec-optimize.ts``.

Runs between ANF lowering (pass 4) and stack lowering (pass 5).
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Optional

from runar_compiler.ir.types import (
    bigint_json_value,
    ANFBinding,
    ANFMethod,
    ANFProgram,
    ANFValue,
)
# DCE pass lives in its own discrete module now (frontend/dce.py).
# Re-import its public helpers so the EC optimizer below can delegate to it
# instead of duplicating the dead-binding sweep.
from runar_compiler.frontend.dce import (
    eliminate_dead_bindings as _eliminate_dead_bindings,
    collect_refs as _collect_refs,
    has_side_effect as _has_side_effect,
)


# ---------------------------------------------------------------------------
# secp256k1 constants
# ---------------------------------------------------------------------------

CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GEN_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GEN_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
INFINITY_HEX = "0" * 128
G_HEX = f"{GEN_X:064x}{GEN_Y:064x}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def optimize_ec(program: ANFProgram) -> ANFProgram:
    """Return a new program with EC operations algebraically simplified."""
    # Only deepcopy and run dead binding elimination if something changed.
    any_changed = False
    for method in program.methods:
        if _has_ec_calls(method):
            any_changed = True
            break

    if not any_changed:
        return program

    # N-097: the has-EC-call check above is only a fast path (a rule can only
    # fire on an EC call, at any depth since N-201). The gate is the TS reference's
    # (anf-ec.ts optimizeEC): dead binding elimination runs over EVERY method
    # iff a rewrite fired in ANY method, else the program is returned
    # untouched, dead bindings included.
    # N-201: the names each method references before any rewrite -- the
    # candidate set of the nested prune below.
    candidates: list[set[str]] = []
    for method in program.methods:
        refs: set[str] = set()
        for binding in method.body:
            _collect_refs(binding.value, refs)
        candidates.append(refs)

    result = deepcopy(program)
    fired = False
    for method in result.methods:
        if _optimize_method(method, result.properties):
            fired = True
    if not fired:
        return program

    # Dead binding elimination
    for method, refs in zip(result.methods, candidates):
        _eliminate_dead_bindings(method)
        # N-201: a rewrite inside an if arm or a loop body orphans its
        # operands there, and the DCE above filters only the top level; an
        # orphan left in an arm unbalances the arms (the N-446 hazard). Same
        # candidate rule as the constant folder's prune.
        _eliminate_dead_bindings(method, refs)
        # N-113: drop the inner ecMul/ecMulGen calls a fusion orphaned whose
        # abort is still performed, then prune what that orphans.
        while _remove_gate_subsumed_ec_calls(method, refs):
            _eliminate_dead_bindings(method, refs)
    return result


def _remove_gate_subsumed_ec_calls(method: ANFMethod, candidates: set[str]) -> bool:
    """N-113 (the TS reference's anf-ec.ts removeGateSubsumedEcCalls): remove
    dead scalar multiplications whose only effect, a possible abort, is
    provably still performed. Mutates ``method``; True when anything went.

    - ``ecMulGen(<const k>)`` cannot abort: its point is the fixed generator,
      which passes ecMul's operand gate, and the ladder reduces any k.
    - ``ecMul(q, <const k>)`` aborts exactly when its operand gate
      ``q === O || ecOnCurve(q)`` fails (R-157). It may go when a WITNESS
      performs the same gate: another ``ecMul(q', _)``, q' the same binding as
      q (F-269), not itself removable, in the same scope or an ENCLOSING one --
      never a nested one, which runs only on some paths.
    - ``ecNegate`` is never removed: R7, R8 and R8r rely on it as a gate.

    Only a removal candidate goes (a name referenced before the EC pass ran --
    the inner call a fusion orphaned), referenced nowhere in the method now,
    not a private method's return value (F-108) and not one of its if's
    ``results``.
    """
    vm = _ValueMap(_collect_rebound_names(method))
    refs: set[str] = set()

    def index(bindings) -> None:
        for b in bindings or ():
            vm[b.name] = b.value
            _collect_refs(b.value, refs)
            if b.value.kind == "if":
                index(b.value.then)
                index(b.value.else_)
            elif b.value.kind == "loop":
                index(b.value.body)

    index(method.body)
    keep_last = method.name != "constructor" and not method.is_public

    def removable(b: ANFBinding, protect: set[str], is_return: bool) -> bool:
        v = b.value
        if (v.kind != "call" or is_return or b.name not in candidates
                or b.name in refs or b.name in protect):
            return False
        args = v.args or []
        if v.func == "ecMulGen":
            return len(args) == 1 and _get_const_int(args[0], vm) is not None
        if v.func == "ecMul":
            return (len(args) == 2 and _get_const_int(args[1], vm) is not None
                    and _stable(args[0], vm))
        return False

    def filter_scope(bindings, outer: list[str], protect: set[str], top_level: bool):
        bindings = bindings or []
        n = len(bindings)
        is_cand = [removable(b, protect, top_level and keep_last and i == n - 1)
                   for i, b in enumerate(bindings)]
        witnesses = list(outer)
        for i, b in enumerate(bindings):
            v = b.value
            if (not is_cand[i] and v.kind == "call" and v.func == "ecMul"
                    and len(v.args or []) == 2):
                c = _canonical(v.args[0], vm)
                if c is not None:
                    witnesses.append(c)
        changed = False
        out = []
        for i, b in enumerate(bindings):
            v = b.value
            if is_cand[i] and (v.func == "ecMulGen" or _canonical(v.args[0], vm) in witnesses):
                changed = True
                continue
            if v.kind == "if":
                results = set(v.results or [])
                then_b = filter_scope(v.then, witnesses, results, False)
                else_b = filter_scope(v.else_, witnesses, results, False)
                if then_b is not None or else_b is not None:
                    changed = True
                    if then_b is not None:
                        v.then = then_b
                    if else_b is not None:
                        v.else_ = else_b
            elif v.kind == "loop":
                body_b = filter_scope(v.body, witnesses, set(), False)
                if body_b is not None:
                    changed = True
                    v.body = body_b
            out.append(b)
        return out if changed else None

    body = filter_scope(method.body, [], set(), True)
    if body is None:
        return False
    method.body = body
    return True


def _has_ec_calls(method: ANFMethod) -> bool:
    """Check if a method has any EC intrinsic call, at any depth (N-201: if
    arms and loop bodies are rewritten too)."""
    ec_funcs = {"ecAdd", "ecMul", "ecMulGen", "ecNegate", "ecOnCurve",
                "ecModReduce", "ecEncodeCompressed", "ecMakePoint", "ecPointX", "ecPointY"}

    def walk(bindings) -> bool:
        for binding in bindings or ():
            v = binding.value
            if v.kind == "call" and v.func in ec_funcs:
                return True
            if v.kind == "if" and (walk(v.then) or walk(v.else_)):
                return True
            if v.kind == "loop" and walk(v.body):
                return True
        return False

    return walk(method.body)


# ---------------------------------------------------------------------------
# Per-method optimization
# ---------------------------------------------------------------------------

def _collect_used_names(method: ANFMethod, properties) -> set[str]:
    """F-086: every name the method already uses -- binding names at any
    depth (if/loop arms included), loop iteration variables, params, and the
    contract's properties. A scalar-fusing rewrite mints a new binding; ANF is
    single-assignment and stack lowering resolves a name to its shallowest
    slot, so a minted name that is already in use silently aliases the two
    values. ``--ir`` input chooses these names freely.
    """
    used: set[str] = {p.name for p in properties}
    used.update(p.name for p in method.params)

    def walk(bindings) -> None:
        for b in bindings or ():
            used.add(b.name)
            v = b.value
            if v.kind in ("load_param", "load_prop") and v.name is not None:
                used.add(v.name)
            elif v.kind == "if":
                walk(v.then)
                walk(v.else_)
            elif v.kind == "loop":
                if v.iter_var is not None:
                    used.add(v.iter_var)
                walk(v.body)

    walk(method.body)
    return used


class _ValueMap(dict):
    """Binding name -> value, plus the method's rebound names (F-269, see _canonical)."""

    def __init__(self, rebound: set[str]):
        super().__init__()
        self.rebound = rebound

    def nested_scope(self, hidden: Optional[str] = None) -> "_ValueMap":
        """N-201: the map an if arm or a loop body starts from (the TS
        ValueMap.nestedScope) -- every binding visible at the if/loop, and
        nothing the nested scope binds flows back out. ``hidden`` is a loop's
        iteration variable, never resolved through an outer binding."""
        scope = _ValueMap(self.rebound)
        scope.update(self)
        if hidden is not None:
            scope.pop(hidden, None)
        return scope


def _collect_rebound_names(method: ANFMethod) -> set[str]:
    """F-269: every name bound more than once in the method -- binding names at
    any depth (if/loop arms included) and loop iteration variables (the TS
    collectReboundNames). _canonical never resolves an alias through one."""
    seen: set[str] = set()
    rebound: set[str] = set()

    def bind(name: str) -> None:
        if name in seen:
            rebound.add(name)
        else:
            seen.add(name)

    def walk(bindings) -> None:
        for b in bindings:
            bind(b.name)
            v = b.value
            if v.kind == "if":
                walk(v.then or [])
                walk(v.else_ or [])
            elif v.kind == "loop":
                if v.iter_var is not None:
                    bind(v.iter_var)
                walk(v.body or [])

    walk(method.body)
    return rebound


def _optimize_method(method: ANFMethod, properties) -> bool:
    """Rewrite one method's EC calls -- top level, if arms and loop bodies
    (N-201) -- to a fixed point; True iff a rule fired."""
    rebound = _collect_rebound_names(method)
    used_names = _collect_used_names(method, properties)
    fired = False
    while True:
        # N-460: the fusion guard's referrer counts, once per sweep.
        referrers = _count_referrers(method.body, method)
        new_body = _optimize_body(method.body, _ValueMap(rebound), None, used_names,
                                  referrers, frozenset())
        if new_body is None:
            break
        method.body = new_body
        fired = True
    return fired


class _FusionScope:
    """N-460 -- what a fusing rule (R9, R10, R11) needs to know at its fire
    site (the TS ``FusionScope`` in anf-ec.ts).

    A fusion replaces the outer call with ONE new scalar multiplication, so it
    shrinks the script only if _remove_gate_subsumed_ec_calls then drops an
    inner call it read. Each fusing rule therefore fires only when at least
    one of its inner operands is ELIMINABLE (_fusion_eliminates):

    - every name on its alias chain (the operand, each ``@ref:`` hop, the call
      binding itself -- _canonical's walk) has exactly one referrer: the
      rewritten binding for the operand, the previous hop for the rest. Any
      other reader keeps the inner call alive after the fusion;
    - the call is an ``ecMulGen`` bound in the current scope or an enclosing
      one inside the same loop body (``frame``). It needs no witness, but one
      bound outside a loop the fusion sits in would trade one multiplication
      for one per iteration;
    - or the call is an ``ecMul`` bound in the current scope itself
      (``local``): the fused ``ecMul`` on the same point is then its witness.
      One bound in an enclosing scope has no witness (the fused call is
      nested) and stays.

    ``referrers`` is computed once per sweep, from the body the sweep starts
    with (_count_referrers), and not updated as the sweep rewrites. A rewrite
    only adds a reference to a name its own binding, or the inner binding it
    lifts from, already read, so a stale count is never too low. Every tier
    computes it the same way, because which rules fire decides the bytes."""

    def __init__(self, referrers: dict[str, int], local: frozenset, frame: frozenset):
        self.referrers = referrers
        self.local = local
        self.frame = frame


def _count_referrers(body, method: ANFMethod) -> dict[str, int]:
    """N-460: referrer count per name -- the bindings, at any depth, whose
    value reads it (once per binding, however many operands name it; an ``if``
    reads its ``cond``, its arms' bindings are counted themselves), plus one
    for each name in an ``if``'s ``results`` and one for a private method's
    return binding (F-108): the two things _remove_gate_subsumed_ec_calls
    protects."""
    counts: dict[str, int] = {}

    def walk(bindings) -> None:
        for b in bindings or ():
            v = b.value
            reads: set[str] = set()
            if v.kind == "if":
                reads.add(v.cond)
                reads.update(v.results or ())
            elif v.kind != "loop":
                _collect_refs(v, reads)
            for name in reads:
                counts[name] = counts.get(name, 0) + 1
            if v.kind == "if":
                walk(v.then)
                walk(v.else_)
            elif v.kind == "loop":
                walk(v.body)

    walk(body)
    if method.name != "constructor" and not method.is_public and body:
        last = body[-1].name
        counts[last] = counts.get(last, 0) + 1
    return counts


def _fusion_eliminates(operands: list[str], vm: dict[str, ANFValue], scope: _FusionScope) -> bool:
    """N-460: does fusing these inner operands let at least one inner call go?"""
    for operand in operands:
        c = _canonical(operand, vm)
        if c is None:
            continue
        # _canonical already walked this chain, so every hop is an @ref:.
        cur = operand
        single = True
        while True:
            if scope.referrers.get(cur, 0) != 1:
                single = False
                break
            if cur == c:
                break
            cur = vm[cur].const_string[5:]
        if not single:
            continue
        v = vm.get(c)
        if v is None or v.kind != "call":
            continue
        if (v.func == "ecMulGen" and c in scope.frame) or (v.func == "ecMul" and c in scope.local):
            return True
    return False


def _optimize_body(body, outer: _ValueMap, hidden: Optional[str],
                   used_names: set[str], referrers: dict[str, int],
                   outer_frame: frozenset) -> Optional[list[ANFBinding]]:
    """One left-to-right sweep over a scope (the TS optimizeBodyOnce): each
    binding is tried once against the values of the bindings before it, as
    already rewritten in this sweep. N-201: it descends into if arms (then
    before else) and loop bodies at the position of their binding, each with
    its own scope (_ValueMap.nested_scope). Returns None when no rule fired."""
    value_map = outer.nested_scope(hidden)
    # N-460: an ``if`` arm sees its enclosing frame, a loop body starts a new one.
    local = frozenset(b.name for b in body or ())
    scope = _FusionScope(referrers, local, outer_frame | local)
    new_body: list[ANFBinding] = []
    changed = False
    for binding in body or []:
        v = binding.value
        if v.kind in ("if", "loop"):
            value_map[binding.name] = v
            if v.kind == "if":
                then_b = _optimize_body(v.then, value_map, None, used_names, referrers, scope.frame)
                else_b = _optimize_body(v.else_, value_map, None, used_names, referrers, scope.frame)
                if then_b is not None or else_b is not None:
                    if then_b is not None:
                        v.then = then_b
                    if else_b is not None:
                        v.else_ = else_b
                    changed = True
            else:
                body_b = _optimize_body(v.body, value_map, v.iter_var, used_names, referrers, frozenset())
                if body_b is not None:
                    v.body = body_b
                    changed = True
            new_body.append(binding)
            continue
        # `new_body` doubles as the prelude list: a rule that folds a new
        # constant appends its binding here, i.e. immediately BEFORE the
        # binding being rewritten (see _fresh_const_name).
        prelude_start = len(new_body)
        value_map[binding.name] = v
        optimized = _try_optimize(v, value_map, new_body, used_names, scope, binding.name)
        if optimized is not None:
            # N-218: every helper a rewrite mints (the N-104/N-251 gate
            # bindings, the fused-scalar helper) takes the rewritten
            # binding's own source_loc, mirroring F-343 in the TS
            # reference (anf-ec.ts optimizeBodyOnce) -- it exists only
            # because of that source expression, and stack lowering maps
            # opcodes through binding.source_loc.
            for helper in new_body[prelude_start:]:
                helper.source_loc = binding.source_loc
            binding = ANFBinding(name=binding.name, value=optimized, source_loc=binding.source_loc)
            changed = True
        value_map[binding.name] = binding.value
        new_body.append(binding)
    return new_body if changed else None


# ---------------------------------------------------------------------------
# Optimization rules
# ---------------------------------------------------------------------------

def _try_optimize(v: ANFValue, vm: dict[str, ANFValue],
                  prelude: list[ANFBinding],
                  used_names: set[str],
                  scope: _FusionScope,
                  name: str = "") -> Optional[ANFValue]:
    if v.kind != "call" or v.func is None or v.args is None:
        return None

    func = v.func
    args = v.args

    # Rule 1: ecAdd(x, INFINITY) -> x, keeping ecAdd's operand gate (N-104)
    if func == "ecAdd" and len(args) == 2:
        if _is_infinity(args[1], vm):
            _emit_operand_gate(False, name, args[0], vm, prelude, used_names)
            return _make_ref(args[0])

    # Rule 2: ecAdd(INFINITY, x) -> x, keeping ecAdd's operand gate (N-104)
    if func == "ecAdd" and len(args) == 2:
        if _is_infinity(args[0], vm):
            _emit_operand_gate(False, name, args[1], vm, prelude, used_names)
            return _make_ref(args[1])

    # Rule 3: ecMul(x, 1) -> x, keeping ecMul's operand gate (N-104)
    if func == "ecMul" and len(args) == 2:
        if _is_const_int(args[1], 1, vm):
            _emit_operand_gate(True, name, args[0], vm, prelude, used_names)
            return _make_ref(args[0])

    # Rule 4: ecMul(x, 0) -> INFINITY, keeping ecMul's operand gate (N-104)
    if func == "ecMul" and len(args) == 2:
        if _is_const_int(args[1], 0, vm):
            _emit_operand_gate(True, name, args[0], vm, prelude, used_names)
            return _make_const_hex(INFINITY_HEX)

    # Rule 5: ecMulGen(0) -> INFINITY
    if func == "ecMulGen" and len(args) == 1:
        if _is_const_int(args[0], 0, vm):
            return _make_const_hex(INFINITY_HEX)

    # Rule 6: ecMulGen(1) -> G
    if func == "ecMulGen" and len(args) == 1:
        if _is_const_int(args[0], 1, vm):
            return _make_const_hex(G_HEX)

    # Rule 7: ecNegate(ecNegate(x)) -> x
    if func == "ecNegate" and len(args) == 1:
        inner = _resolve(args[0], vm)
        # F-269 attempt 2: x is lifted out of the inner binding and re-emitted
        # here, so it must denote one value at both sites.
        if (inner is not None and inner.kind == "call" and inner.func == "ecNegate" and inner.args
                and len(inner.args) == 1 and _stable(inner.args[0], vm)):
            return _make_ref(inner.args[0])

    # Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY, keeping the adder's y = 0 abort (N-251)
    if func == "ecAdd" and len(args) == 2:
        neg = _resolve(args[1], vm)
        if neg is not None and neg.kind == "call" and neg.func == "ecNegate" and neg.args and len(neg.args) == 1:
            if _same_binding(args[0], neg.args[0], vm):
                _emit_neg_cancel_gate(name, args[0], vm, prelude, used_names)
                return _make_const_hex(INFINITY_HEX)

    # Rule 8r (`ec-add-negate-cancel-reversed`): ecAdd(ecNegate(x), x) -> INFINITY
    #
    # The mirror of Rule 8. It has always been in optimizer/ec-rules.json and the
    # Go tier -- whose rule engine executes that file directly -- performed it;
    # the six hand-ported tiers implemented only the forward direction, so the
    # same ANF compiled to a 1808-byte script in Go and a 26140-byte one
    # everywhere else (R-034 / CL-BUG-028).
    #
    # Placed after Rule 8 and before Rules 9/10/11 to match the JSON's rule
    # order, which is the order the Go engine tries them in.
    if func == "ecAdd" and len(args) == 2:
        neg = _resolve(args[0], vm)
        if neg is not None and neg.kind == "call" and neg.func == "ecNegate" and neg.args and len(neg.args) == 1:
            if _same_binding(args[1], neg.args[0], vm):
                # The gate reads the ecNegate operand: the name the JSON's `$x`
                # binds first, as the Go engine binds it (differs from args[1]
                # only through an alias, F-269).
                _emit_neg_cancel_gate(name, neg.args[0], vm, prelude, used_names)
                return _make_const_hex(INFINITY_HEX)

    # Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2 mod N)
    if func == "ecMul" and len(args) == 2:
        inner = _resolve(args[0], vm)
        k2 = _get_const_int(args[1], vm)
        if (inner is not None and k2 is not None and inner.kind == "call" and inner.func == "ecMul" and inner.args
                and len(inner.args) == 2 and _stable(inner.args[0], vm)):
            k1 = _get_const_int(inner.args[1], vm)
            if k1 is not None and _fusion_eliminates([args[0]], vm, scope):
                combined = (k1 * k2) % CURVE_N
                return _make_call("ecMul", [inner.args[0], _fresh_const_name(name, combined, vm, prelude, used_names)])

    # Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen(k1+k2 mod N)
    if func == "ecAdd" and len(args) == 2:
        left = _resolve(args[0], vm)
        right = _resolve(args[1], vm)
        if (left is not None and right is not None
                and left.kind == "call" and left.func == "ecMulGen" and left.args and len(left.args) == 1
                and right.kind == "call" and right.func == "ecMulGen" and right.args and len(right.args) == 1):
            k1 = _get_const_int(left.args[0], vm)
            k2 = _get_const_int(right.args[0], vm)
            if k1 is not None and k2 is not None and _fusion_eliminates(args, vm, scope):
                combined = (k1 + k2) % CURVE_N
                return _make_call("ecMulGen", [_fresh_const_name(name, combined, vm, prelude, used_names)])

    # Rule 11: ecAdd(ecMul(k1,p), ecMul(k2,p)) -> ecMul(k1+k2, p) when same p
    if func == "ecAdd" and len(args) == 2:
        left = _resolve(args[0], vm)
        right = _resolve(args[1], vm)
        if (left is not None and right is not None
                and left.kind == "call" and left.func == "ecMul" and left.args and len(left.args) == 2
                and right.kind == "call" and right.func == "ecMul" and right.args and len(right.args) == 2):
            if _same_binding(left.args[0], right.args[0], vm):
                k1 = _get_const_int(left.args[1], vm)
                k2 = _get_const_int(right.args[1], vm)
                if k1 is not None and k2 is not None and _fusion_eliminates(args, vm, scope):
                    combined = (k1 + k2) % CURVE_N
                    return _make_call("ecMul", [left.args[0], _fresh_const_name(name, combined, vm, prelude, used_names)])

    # Rule 12: ecMul(k, G) -> ecMulGen(k)
    if func == "ecMul" and len(args) == 2:
        if _is_generator(args[0], vm):
            return _make_call("ecMulGen", [args[1]])

    return None


# ---------------------------------------------------------------------------
# Helpers -- value inspection
# ---------------------------------------------------------------------------

def _resolve(name: str, vm: dict[str, ANFValue]) -> Optional[ANFValue]:
    """Resolve a binding name to its ANFValue, following @ref: aliases (F-269).
    None for a name with no fixed identity (see _canonical)."""
    c = _canonical(name, vm)
    return None if c is None else vm.get(c)


def _stable(name: str, vm: dict[str, ANFValue]) -> bool:
    """F-269 attempt 2: may a name lifted out of an earlier binding be emitted
    at the current site? Only when it denotes one value (R7, R9)."""
    return _canonical(name, vm) is not None


def _is_infinity(name: str, vm: dict[str, ANFValue]) -> bool:
    val = _resolve(name, vm)
    if val is None:
        return False
    return val.kind == "load_const" and val.const_string == INFINITY_HEX


def _is_generator(name: str, vm: dict[str, ANFValue]) -> bool:
    val = _resolve(name, vm)
    if val is None:
        return False
    return val.kind == "load_const" and val.const_string == G_HEX


def _is_const_int(name: str, n: int, vm: dict[str, ANFValue]) -> bool:
    val = _resolve(name, vm)
    if val is None:
        return False
    return val.kind == "load_const" and val.const_big_int == n


def _get_const_int(name: str, vm: dict[str, ANFValue]) -> Optional[int]:
    val = _resolve(name, vm)
    if val is None:
        return None
    if val.kind == "load_const" and val.const_big_int is not None:
        return val.const_big_int
    return None


def _same_binding(a: str, b: str, vm: dict[str, ANFValue]) -> bool:
    """Check if two binding names refer to the same underlying value. Never for
    a name with no fixed identity."""
    ca = _canonical(a, vm)
    return ca is not None and ca == _canonical(b, vm)


def _canonical(name: str, vm: dict[str, ANFValue]) -> Optional[str]:
    """F-269 (user decision R77): the binding `name` ultimately names, following
    load_const "@ref:<x>" aliases -- pass 04's `const y = <expr>` and the ones
    R1/R2/R3/R7 leave behind (the TS canonicalName in anf-ec.ts).

    None when `name` has no position-independent identity: ANF re-emits a
    local's name when the source reassigns it (top level or in an if/loop
    arm), so a REBOUND name means different values at different sites. Two
    uses of one are not "the same $x", and nothing lifted out of an earlier
    binding may name one (F-269 attempt 2). An alias cycle (only hand-written
    --ir) is None too. A hop is never taken INTO a rebound name: the chain
    stops at the last name bound once, which is itself a fixed value, and its
    value is the opaque alias. Matching only -- rewrites emit the literal names
    they matched.

    This used to look for the alias on `load_param` values, a kind pass 04
    never gives one, so it never followed anything."""
    rebound = getattr(vm, "rebound", set())
    if name in rebound:
        return None
    seen: set[str] = {name}
    current = name
    while True:
        val = vm.get(current)
        if (val is None or val.kind != "load_const" or not isinstance(val.const_string, str)
                or len(val.const_string) <= 5 or not val.const_string.startswith("@ref:")):
            return current
        nxt = val.const_string[5:]
        if nxt in rebound:
            return current
        if nxt in seen:
            return None
        seen.add(nxt)
        current = nxt


# ---------------------------------------------------------------------------
# Helpers -- value construction
# ---------------------------------------------------------------------------

def _make_ref(name: str) -> ANFValue:
    """Create a load_const that aliases another binding via @ref:."""
    return ANFValue(kind="load_const", const_string=f"@ref:{name}", raw_value=f"@ref:{name}")


def _make_const_hex(hex_str: str) -> ANFValue:
    return ANFValue(kind="load_const", const_string=hex_str, raw_value=hex_str)


def _make_const_int(n: int) -> ANFValue:
    # A folded EC scalar is a value mod n, routinely far beyond
    # Number.MAX_SAFE_INTEGER, and it now reaches the emitted IR JSON. Use the
    # tier's canonical encoding (bare number when a double carries it
    # losslessly, else the decimal digits with the JS BigInt `n` suffix, as a
    # string) rather than a bare Python int, which `--emit-ir` would write as
    # an unquoted 256-bit JSON number that every double-based consumer
    # silently truncates. Same encoding as
    # frontend/anf_lower.py::_make_load_const_int.
    raw = bigint_json_value(n)
    return ANFValue(kind="load_const", const_big_int=n, const_int=n, raw_value=raw)


def _make_call(func: str, args: list[str]) -> ANFValue:
    return ANFValue(kind="call", func=func, args=args)


FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def _emit_operand_gate(of_mul: bool, base: str, q: str, vm: dict[str, ANFValue],
                       prelude: list[ANFBinding], used_names: set[str]) -> None:
    """N-104 -- the operand gate a rewrite must leave behind.

    Byte-for-byte the TS reference (emitAddOperandGate / emitMulOperandGate in
    packages/runar-compiler/src/optimizer/anf-ec.ts) and the "gate" entries in
    optimizer/ec-rules.json::

        ecAdd: assert(ecPointX(q) < p && ecPointY(q) < p)  width (CL-BUG-095) + canonicity (R-117)
        ecMul: assert(q === O || ecOnCurve(q))              on-curve-or-O (R-157)

    R1-R4 replace a builtin whose first act is to validate q; without this a
    malformed or off-curve q was accepted by the default compile and aborted
    under disableEcOptimizer. Built only from forms no rule matches, so the
    fixed-point loop cannot rewrite it on a later pass. Names follow the TS
    ``freshName``: ``<base><suffix>``, else the first unused ``..._<i>``.
    """
    def add(suffix: str, value: ANFValue) -> str:
        name = base + suffix
        i = 1
        while name in used_names:
            name = f"{base}{suffix}_{i}"
            i += 1
        used_names.add(name)
        vm[name] = value
        prelude.append(ANFBinding(name=name, value=value))
        return name

    if not of_mul:
        px = add("_px", _make_call("ecPointX", [q]))
        py = add("_py", _make_call("ecPointY", [q]))
        fp = add("_fp", _make_const_int(FIELD_P))
        x_ok = add("_pxok", ANFValue(kind="bin_op", op="<", left=px, right=fp))
        y_ok = add("_pyok", ANFValue(kind="bin_op", op="<", left=py, right=fp))
        ok = add("_ok", ANFValue(kind="bin_op", op="&&", left=x_ok, right=y_ok))
    else:
        inf = add("_inf", _make_const_hex(INFINITY_HEX))
        is_inf = add("_isinf", ANFValue(kind="bin_op", op="===", left=q, right=inf, result_type="bytes"))
        on_curve = add("_oncurve", _make_call("ecOnCurve", [q]))
        ok = add("_ok", ANFValue(kind="bin_op", op="||", left=is_inf, right=on_curve))
    add("_gate", ANFValue(kind="assert", raw_value=ok, value_ref=ok))


def _emit_neg_cancel_gate(base: str, q: str, vm: dict[str, ANFValue],
                          prelude: list[ANFBinding], used_names: set[str]) -> None:
    """N-251 -- the gate R8/R8r (ecAdd(q, ecNegate(q)) -> O and its mirror)
    must leave behind (user decision R96).

    Byte-for-byte the TS reference (emitNegCancelGate in
    packages/runar-compiler/src/optimizer/anf-ec.ts)::

        assert(ecPointX(q) === 0 || ecPointY(q) !== 0)

    The replaced ecAdd doubles exactly when y(q) = 0, and N-110 made the adder
    abort on a doubling with px != 0 and py == 0; the px == 0 term keeps
    O + O = O. Width and canonicity are checked by the inner ecNegate(q) call,
    which is never dead-code-eliminated. Names as in _emit_operand_gate.
    """
    def add(suffix: str, value: ANFValue) -> str:
        name = base + suffix
        i = 1
        while name in used_names:
            name = f"{base}{suffix}_{i}"
            i += 1
        used_names.add(name)
        vm[name] = value
        prelude.append(ANFBinding(name=name, value=value))
        return name

    px = add("_px", _make_call("ecPointX", [q]))
    py = add("_py", _make_call("ecPointY", [q]))
    zero = add("_zero", _make_const_int(0))
    x_zero = add("_pxz", ANFValue(kind="bin_op", op="===", left=px, right=zero))
    y_non_zero = add("_pynz", ANFValue(kind="bin_op", op="!==", left=py, right=zero))
    ok = add("_ok", ANFValue(kind="bin_op", op="||", left=x_zero, right=y_non_zero))
    add("_gate", ANFValue(kind="assert", raw_value=ok, value_ref=ok))


def _fresh_const_name(base: str, value: int, vm: dict[str, ANFValue],
                      prelude: list[ANFBinding], used_names: set[str]) -> str:
    """Bind a freshly folded constant and return its name.

    This is needed when optimization produces a new constant (e.g. k1*k2)
    that needs to be referenced by name in a call.

    The binding is appended to *prelude* — the rebuilt method body, at the
    point just before the binding currently being rewritten — as well as
    registered in the value map. Registering it in the value map alone is not
    enough: stack lowering walks the body, so a call referencing a name that
    never got a binding dies with "value '<name>' not found on stack".
    Mirrors AnfOptimize.freshConstName (Java), buildOpHelper (Go) and the
    `newBindings` list in anf-ec.ts (TypeScript).

    The name follows the TS ``freshName(`${binding.name}_k`, usedNames)``:
    ``<base>_k``, else the first unused ``<base>_k_<i>`` (F-086: against every
    name the method already uses, see _collect_used_names), and is reserved
    there. F-191: it is derived from the program alone -- no process-global
    counter -- so the same program always gets the same names.
    """
    stem = f"{base}_k"
    name = stem
    i = 1
    while name in used_names:
        name = f"{stem}_{i}"
        i += 1
    used_names.add(name)
    const = _make_const_int(value)
    vm[name] = const
    prelude.append(ANFBinding(name=name, value=const))
    return name


# ---------------------------------------------------------------------------
# Dead binding elimination
# ---------------------------------------------------------------------------
#
# The DCE pass lives in its own discrete module now (frontend/dce.py).
# The intra-module helpers `_eliminate_dead_bindings`, `_collect_refs`, and
# `_has_side_effect` are imported at the top of this file from `frontend.dce`
# so the EC optimizer delegates to the canonical implementation.
