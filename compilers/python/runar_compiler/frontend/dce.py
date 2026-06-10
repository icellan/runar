"""Dead Code Elimination pass for ANF IR.

Removes bindings whose results are never referenced by other bindings,
preserving bindings with observable side effects (assert, update_prop,
check_preimage, add_output, add_raw_output, add_data_output, call,
method_call, raw_script). Iterates to a fixed point so transitively
dead bindings are also removed.

This module is the canonical, standalone DCE pass for the Python
compiler. It mirrors the Zig reference implementation in
``compilers/zig/src/passes/dce.zig``. The earlier inline implementation
in ``anf_optimize.py`` has been surgically extracted here.

Behaviour: byte-for-byte identical to the previous inline DCE in
``anf_optimize.py``. Verified by the conformance suite (cross-tier hex
parity) and the unknown-kind exhaustiveness tests.
"""

from __future__ import annotations

from runar_compiler.ir.types import ANFBinding, ANFMethod, ANFProgram, ANFValue
from runar_compiler.ir.unknown_anf_kind_error import UnknownANFKindError


# All ANF kinds recognized by the dispatchers below. Used as an allowlist so
# an unknown kind raises ``UnknownANFKindError`` instead of silently being
# treated as zero-refs (collect_refs) or side-effect-free (has_side_effect).
# Mirrors ``KNOWN_KINDS`` in ``runar_compiler.ir.loader``.
_DCE_KNOWN_KINDS: frozenset[str] = frozenset({
    "load_param",
    "load_prop",
    "load_const",
    "bin_op",
    "unary_op",
    "call",
    "method_call",
    "if",
    "loop",
    "assert",
    "update_prop",
    "get_state_script",
    "check_preimage",
    "deserialize_state",
    "add_output",
    "add_raw_output",
    "add_data_output",
    "array_literal",
    "raw_script",
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def eliminate_dead_code(program: ANFProgram) -> ANFProgram:
    """Eliminate dead bindings across every method in the program.

    Mutates the program in place and returns it.
    """
    for method in program.methods:
        eliminate_dead_bindings(method)
    return program


def eliminate_dead_bindings(method: ANFMethod) -> None:
    """Remove bindings whose results are never referenced.

    Uses iterative elimination to handle transitive dead code
    (e.g., if A references B and A is dead, B may also become dead).
    """
    current = method.body
    changed = True

    while changed:
        changed = False
        used: set[str] = set()
        for binding in current:
            collect_refs(binding.value, used)

        filtered: list[ANFBinding] = []
        for binding in current:
            if binding.name in used or has_side_effect(binding.value):
                filtered.append(binding)
            else:
                changed = True

        current = filtered

    method.body = current


# ---------------------------------------------------------------------------
# Core algorithm
# ---------------------------------------------------------------------------

def collect_refs(v: ANFValue, used: set[str]) -> None:
    """Walk an ANFValue and collect all binding name references.

    Matches TS ``collectRefsFromValue`` in optimizer/dce.ts.

    Raises ``UnknownANFKindError`` if the value's kind is not in the known
    set. A silent fall-through would let DCE drop a live binding because
    its refs go uncollected.
    """
    if v.kind not in _DCE_KNOWN_KINDS:
        raise UnknownANFKindError(v.kind, "constant-fold.collectRefsFromValue")

    if v.kind == "load_param":
        # Do NOT track @ref: targets here — matches TS collectRefsFromValue
        # which breaks on load_param without collecting refs.
        return
    if v.kind == "load_const":
        # Track @ref: aliases in load_const values to prevent DCE
        if v.const_string is not None and v.const_string.startswith("@ref:"):
            used.add(v.const_string[5:])
        return
    if v.kind in ("load_prop", "get_state_script"):
        return
    if v.left is not None:
        used.add(v.left)
    if v.right is not None:
        used.add(v.right)
    if v.operand is not None:
        used.add(v.operand)
    if v.cond is not None:
        used.add(v.cond)
    if v.value_ref is not None:
        used.add(v.value_ref)
    if v.object is not None:
        used.add(v.object)
    if v.satoshis is not None:
        used.add(v.satoshis)
    if v.preimage is not None:
        used.add(v.preimage)
    if v.args is not None:
        for arg in v.args:
            used.add(arg)
    if v.state_values is not None:
        for sv in v.state_values:
            used.add(sv)
    if v.script_bytes is not None:
        used.add(v.script_bytes)
    if v.elements is not None:
        for elem in v.elements:
            used.add(elem)
    if v.then is not None:
        for b in v.then:
            collect_refs(b.value, used)
    if v.else_ is not None:
        for b in v.else_:
            collect_refs(b.value, used)
    if v.body is not None:
        for b in v.body:
            collect_refs(b.value, used)


def has_side_effect(v: ANFValue) -> bool:
    """Return True if this value kind has observable side effects.

    Raises ``UnknownANFKindError`` if the value's kind is not in the known
    set. A silent ``return False`` would let DCE eliminate a new
    side-effecting ANF kind, producing scripts that omit observable
    behavior.
    """
    if v.kind not in _DCE_KNOWN_KINDS:
        raise UnknownANFKindError(v.kind, "constant-fold.hasSideEffect")

    return v.kind in (
        "assert",
        "update_prop",
        "check_preimage",
        "deserialize_state",
        "add_output",
        "add_raw_output",
        "add_data_output",
        "if",
        "loop",
        "call",
        "method_call",
        # Opaque byte span -- DCE must never eliminate it.
        "raw_script",
    )
