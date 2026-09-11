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

    result = deepcopy(program)
    for method in result.methods:
        _optimize_method(method)
    return result


def _has_ec_calls(method: ANFMethod) -> bool:
    """Check if a method has any EC intrinsic calls."""
    ec_funcs = {"ecAdd", "ecMul", "ecMulGen", "ecNegate", "ecOnCurve",
                "ecModReduce", "ecEncodeCompressed", "ecMakePoint", "ecPointX", "ecPointY"}
    for binding in method.body:
        if binding.value.kind == "call" and binding.value.func in ec_funcs:
            return True
    return False


# ---------------------------------------------------------------------------
# Per-method optimization
# ---------------------------------------------------------------------------

def _optimize_method(method: ANFMethod) -> None:
    value_map: dict[str, ANFValue] = {}
    changed = True
    while changed:
        changed = False
        new_body: list[ANFBinding] = []
        for binding in method.body:
            # `new_body` doubles as the prelude list: a rule that folds a new
            # constant appends its binding here, i.e. immediately BEFORE the
            # binding being rewritten (see _fresh_const_name).
            optimized = _try_optimize(binding.value, value_map, new_body)
            if optimized is not None:
                binding = ANFBinding(name=binding.name, value=optimized, source_loc=binding.source_loc)
                changed = True
            value_map[binding.name] = binding.value
            new_body.append(binding)
        method.body = new_body

    # Dead binding elimination
    _eliminate_dead_bindings(method)


# ---------------------------------------------------------------------------
# Optimization rules
# ---------------------------------------------------------------------------

def _try_optimize(v: ANFValue, vm: dict[str, ANFValue],
                  prelude: list[ANFBinding]) -> Optional[ANFValue]:
    if v.kind != "call" or v.func is None or v.args is None:
        return None

    func = v.func
    args = v.args

    # Rule 1: ecAdd(x, INFINITY) -> x
    if func == "ecAdd" and len(args) == 2:
        if _is_infinity(args[1], vm):
            return _make_ref(args[0])

    # Rule 2: ecAdd(INFINITY, x) -> x
    if func == "ecAdd" and len(args) == 2:
        if _is_infinity(args[0], vm):
            return _make_ref(args[1])

    # Rule 3: ecMul(x, 1) -> x
    if func == "ecMul" and len(args) == 2:
        if _is_const_int(args[1], 1, vm):
            return _make_ref(args[0])

    # Rule 4: ecMul(x, 0) -> INFINITY
    if func == "ecMul" and len(args) == 2:
        if _is_const_int(args[1], 0, vm):
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
        if inner is not None and inner.kind == "call" and inner.func == "ecNegate" and inner.args and len(inner.args) == 1:
            return _make_ref(inner.args[0])

    # Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY
    if func == "ecAdd" and len(args) == 2:
        neg = _resolve(args[1], vm)
        if neg is not None and neg.kind == "call" and neg.func == "ecNegate" and neg.args and len(neg.args) == 1:
            if _same_binding(args[0], neg.args[0], vm):
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
                return _make_const_hex(INFINITY_HEX)

    # Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2 mod N)
    if func == "ecMul" and len(args) == 2:
        inner = _resolve(args[0], vm)
        k2 = _get_const_int(args[1], vm)
        if inner is not None and k2 is not None and inner.kind == "call" and inner.func == "ecMul" and inner.args and len(inner.args) == 2:
            k1 = _get_const_int(inner.args[1], vm)
            if k1 is not None:
                combined = (k1 * k2) % CURVE_N
                return _make_call("ecMul", [inner.args[0], _fresh_const_name(combined, vm, prelude)])

    # Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen(k1+k2 mod N)
    if func == "ecAdd" and len(args) == 2:
        left = _resolve(args[0], vm)
        right = _resolve(args[1], vm)
        if (left is not None and right is not None
                and left.kind == "call" and left.func == "ecMulGen" and left.args and len(left.args) == 1
                and right.kind == "call" and right.func == "ecMulGen" and right.args and len(right.args) == 1):
            k1 = _get_const_int(left.args[0], vm)
            k2 = _get_const_int(right.args[0], vm)
            if k1 is not None and k2 is not None:
                combined = (k1 + k2) % CURVE_N
                return _make_call("ecMulGen", [_fresh_const_name(combined, vm, prelude)])

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
                if k1 is not None and k2 is not None:
                    combined = (k1 + k2) % CURVE_N
                    return _make_call("ecMul", [left.args[0], _fresh_const_name(combined, vm, prelude)])

    # Rule 12: ecMul(k, G) -> ecMulGen(k)
    if func == "ecMul" and len(args) == 2:
        if _is_generator(args[0], vm):
            return _make_call("ecMulGen", [args[1]])

    return None


# ---------------------------------------------------------------------------
# Helpers -- value inspection
# ---------------------------------------------------------------------------

def _resolve(name: str, vm: dict[str, ANFValue]) -> Optional[ANFValue]:
    """Resolve a binding name to its ANFValue, following @ref: aliases."""
    seen: set[str] = set()
    current = name
    while current in vm:
        if current in seen:
            break
        seen.add(current)
        val = vm[current]
        if val.kind == "load_param" and val.name is not None and val.name.startswith("@ref:"):
            current = val.name[5:]
            continue
        return val
    return vm.get(current)


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
    """Check if two binding names refer to the same underlying value."""
    return _canonical(a, vm) == _canonical(b, vm)


def _canonical(name: str, vm: dict[str, ANFValue]) -> str:
    """Follow @ref: chains to get the canonical binding name."""
    seen: set[str] = set()
    current = name
    while current in vm:
        if current in seen:
            break
        seen.add(current)
        val = vm[current]
        if val.kind == "load_param" and val.name is not None and val.name.startswith("@ref:"):
            current = val.name[5:]
            continue
        break
    return current


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
    raw = json.dumps(bigint_json_value(n))
    return ANFValue(kind="load_const", const_big_int=n, const_int=n, raw_value=raw)


def _make_call(func: str, args: list[str]) -> ANFValue:
    return ANFValue(kind="call", func=func, args=args)


# Counter for generating fresh constant binding names
_fresh_counter = 0


def _fresh_const_name(value: int, vm: dict[str, ANFValue],
                      prelude: list[ANFBinding]) -> str:
    """Bind a freshly folded constant and return its name.

    This is needed when optimization produces a new constant (e.g. k1*k2)
    that needs to be referenced by name in a call.

    The binding is appended to *prelude* — the rebuilt method body, at the
    point just before the binding currently being rewritten — as well as
    registered in the value map. Registering it in the value map alone is not
    enough: stack lowering walks the body, so a call referencing a name that
    never got a binding dies with "value '__ec_opt_N' not found on stack".
    Mirrors AnfOptimize.freshConstName (Java), buildOpHelper (Go) and the
    `newBindings` list in anf-ec.ts (TypeScript).
    """
    global _fresh_counter
    _fresh_counter += 1
    name = f"__ec_opt_{_fresh_counter}"
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
