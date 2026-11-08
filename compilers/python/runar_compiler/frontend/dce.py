"""Dead Code Elimination pass for ANF IR.

Removes bindings whose results are never referenced by other bindings,
preserving bindings with observable side effects (assert, update_prop,
check_preimage, add_output, add_raw_output, add_data_output, call,
method_call, raw_script). Iterates to a fixed point so transitively
dead bindings are also removed.

"Results" is plural on purpose (N-140). A binding does not only define
its own ``name``: an ``if`` that merges branch locals also defines every
name in ``results``, and both an ``if`` and a ``loop`` define the names
their nested bindings bind. Liveness used to test ``binding.name in
used`` alone, so an ``if`` named ``t9`` carrying ``results ["a","b"]`` —
a name nothing ever references, because callers reference ``a`` and
``b`` — was deleted whenever its arms happened to be pure, and the
merged locals kept their pre-branch values. See
``conformance/dce/live-if.test.ts``.

R-240: this used to say "the canonical, standalone DCE pass for the
Python compiler". It is canonical — every dead-binding sweep in this
tier comes from here — but it is NOT standalone. Its only pipeline
caller is ``anf_optimize.optimize_ec``, which runs it after the
``if not any_changed: return program`` gate, so a program containing no
EC calls is never swept. ``eliminate_dead_code`` has one other caller,
``compiler._collect_referenced_props``, and that one runs on a
deep-copied probe purely to compute the @embedAlways warning.

The gate is load-bearing. Moving the sweep ahead of it makes this tier
fail to compile 11 of the 78 conformance fixtures (the same 11 the TS
tier fails under the same probe, R-194) — DCE as written removes
bindings stack lowering still needs. That is N-140, and it is a defect
to fix inside DCE before it is a wiring change.

The earlier inline implementation in ``anf_optimize.py`` has been
surgically extracted here.

Behaviour: byte-for-byte identical, at the time of that extraction, to
the previous inline DCE in ``anf_optimize.py``. Verified by the
conformance suite (cross-tier hex parity) and the unknown-kind
exhaustiveness tests.

N-140 is a deliberate behaviour change since: liveness considers
the names a binding DEFINES, not only its own ``name``. F-108 is the other:
a private method's last binding (its return value) is a liveness root.
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


def eliminate_dead_bindings(
    method: ANFMethod, candidates: set[str] | None = None,
) -> None:
    """Remove bindings whose results are never referenced.

    Uses iterative elimination to handle transitive dead code
    (e.g., if A references B and A is dead, B may also become dead).

    N-138: when ``candidates`` is given, only a binding whose name is in it may
    be removed; every other binding is kept as if live. The constant folder uses
    this to drop the operand bindings its own rewrites orphaned (the ``1``
    under a folded ``-1n``) without also deleting bindings that were already
    dead before folding, so fold-ON output does not move for a program the
    folder did not change.
    """
    keep_last = _returns_last_binding(method)
    current = method.body
    changed = True

    while changed:
        changed = False
        own_refs: list[set[str]] = []
        ref_count: dict[str, int] = {}
        for binding in current:
            own: set[str] = set()
            collect_refs(binding.value, own)
            own_refs.append(own)
            for name in own:
                ref_count[name] = ref_count.get(name, 0) + 1

        filtered: list[ANFBinding] = []
        for i, binding in enumerate(current):
            if (
                (keep_last and i == len(current) - 1)
                or (candidates is not None and binding.name not in candidates)
                or is_referenced_externally(binding, own_refs[i], ref_count)
                or has_side_effect(binding.value)
            ):
                filtered.append(binding)
            else:
                changed = True

        current = filtered

        # N-446: the fold also orphans operands INSIDE ``if`` arms and loop
        # bodies (``-5n`` in an else arm). Filtering only the top level left
        # them there, stack lowering pushed them, and the arms ended at
        # different depths. Prune the nested scopes too, then re-filter the
        # top level (a nested removal can orphan a top-level operand).
        if not changed and candidates is not None:
            pruned = _prune_nested_orphans(current, candidates)
            if pruned is not current:
                current = pruned
                changed = True

    method.body = current


def _prune_nested_orphans(
    bindings: list[ANFBinding], candidates: set[str],
) -> list[ANFBinding]:
    """N-446: remove fold-orphaned pure bindings from every nested scope.

    Walks ``if`` arms and ``loop`` bodies recursively; returns ``bindings``
    itself when nothing was removed. A nested binding is removed only if it is
    a candidate (referenced before folding), is referenced by NO binding
    anywhere in the method now (arm bindings can be read after the ``if`` by
    name, so an arm is never filtered against its own references alone), is
    not one of its ``if``'s declared ``results`` (stack lowering requires those
    slots in both arms), is side-effect free, and is not itself an ``if`` /
    ``loop`` (those are recursed into instead). Only the candidate-restricted
    fold prune calls this; the EC-gated DCE stays top-level, so fold-OFF
    output cannot move. Changed bindings are copied, never edited in place.
    """
    import copy

    current = bindings
    while True:
        refs: set[str] = set()
        for b in current:
            collect_refs(b.value, refs)
        changed = False

        def filter_scope(
            scope: list[ANFBinding], nested: bool, protect: set[str],
        ) -> list[ANFBinding]:
            nonlocal changed
            out: list[ANFBinding] = []
            scope_changed = False
            for b in scope:
                v = b.value
                if v.kind == "if":
                    res = set(v.results or [])
                    then_src = v.then or []
                    else_src = v.else_ or []
                    then_b = filter_scope(then_src, True, res)
                    else_b = filter_scope(else_src, True, res)
                    if then_b is not then_src or else_b is not else_src:
                        nv = copy.copy(v)
                        if then_b is not then_src:
                            nv.then = then_b
                        if else_b is not else_src:
                            nv.else_ = else_b
                        nb = copy.copy(b)
                        nb.value = nv
                        out.append(nb)
                        scope_changed = True
                    else:
                        out.append(b)
                elif v.kind == "loop":
                    body_src = v.body or []
                    body = filter_scope(body_src, True, set())
                    if body is not body_src:
                        nv = copy.copy(v)
                        nv.body = body
                        nb = copy.copy(b)
                        nb.value = nv
                        out.append(nb)
                        scope_changed = True
                    else:
                        out.append(b)
                elif (
                    nested
                    and b.name in candidates
                    and b.name not in refs
                    and b.name not in protect
                    and not has_side_effect(v)
                ):
                    scope_changed = True
                else:
                    out.append(b)
            if not scope_changed:
                return scope
            changed = True
            return out

        nxt = filter_scope(current, False, set())
        if not changed:
            return current
        current = nxt


def _returns_last_binding(method: ANFMethod) -> bool:
    """F-108: whether ``method``'s LAST binding is its return value.

    Stack lowering inlines a private method at each ``method_call`` and takes
    that binding as the call's result, so it is a liveness root even though
    nothing inside the method references it; without the root a pure return
    expression (``return n + 1n``) was deleted and the helper emptied. The
    predicate is the one stack lowering uses to collect inlinable private
    methods. A public method's last binding is never a return value.
    """
    return method.name != "constructor" and not method.is_public


def collect_defined_names(binding: ANFBinding, out: set[str]) -> None:
    """Collect every SSA name a binding brings into scope.

    Its own ``name``, plus -- for the two nesting kinds -- an ``if``'s
    declared ``results`` (the merged branch locals / property slots both
    arms leave behind) and the names bound inside ``then``, ``else_`` and a
    ``loop`` body, recursively.

    ``iter_var`` is deliberately absent: it is the loop's own induction
    variable, referenced only from inside the body, so counting it as
    defined would make every non-trivial loop unconditionally live.
    """
    out.add(binding.name)
    v = binding.value
    if v.kind == "if":
        if v.results is not None:
            out.update(v.results)
        for b in v.then or []:
            collect_defined_names(b, out)
        for b in v.else_ or []:
            collect_defined_names(b, out)
    elif v.kind == "loop":
        for b in v.body or []:
            collect_defined_names(b, out)


def is_referenced_externally(
    binding: ANFBinding, own_refs: set[str], ref_count: dict[str, int]
) -> bool:
    """Is any name this binding defines referenced by some OTHER binding?

    ``ref_count`` maps a name to the number of DISTINCT bindings referencing
    it; ``own_refs`` is this binding's own contribution. Subtracting it is
    what keeps the rule from degenerating into "never delete an ``if`` or a
    ``loop``": an arm's bindings almost always reference each other, and
    counting those self-references would make every nesting node immortal.

    For a non-nesting binding this is exactly the old ``binding.name in
    used``: ANF has no self-reference, so ``own_refs`` never holds the
    binding's own name.
    """
    defined: set[str] = set()
    collect_defined_names(binding, defined)
    for name in defined:
        if ref_count.get(name, 0) - (1 if name in own_refs else 0) > 0:
            return True
    return False


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
        # N-356: a reassigned parameter is bound under its own name and read
        # back as `load_param <name>`; count the read so DCE keeps the
        # rebinding. Matches TS collectRefsFromValue.
        if v.name is not None:
            used.add(v.name)
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


# bin_op operators whose opcode can fail at runtime (see ``has_side_effect``).
_PARTIAL_BIN_OPS = frozenset({"/", "%", "&", "|", "^", "<<", ">>"})


def has_side_effect(v: ANFValue) -> bool:
    """Return True if this value kind has observable side effects.

    Raises ``UnknownANFKindError`` if the value's kind is not in the known
    set. A silent ``return False`` would let DCE eliminate a new
    side-effecting ANF kind, producing scripts that omit observable
    behavior.
    """
    if v.kind not in _DCE_KNOWN_KINDS:
        raise UnknownANFKindError(v.kind, "constant-fold.hasSideEffect")

    # Issue #109 (``@embedAlways``): a ``load_prop`` injected to force a readonly
    # field into the deployed locking script carries ``preserve=True``, so DCE
    # must keep it even though nothing references it. Ordinary load_props
    # (``preserve=False``) remain freely eliminable. Mirrors
    # ``compilers/zig/src/passes/dce.zig``.
    if v.kind == "load_prop":
        return v.preserve

    # R-140: ``if`` / ``loop`` are effectful IFF some NESTED binding is.
    #
    # They used to sit in the flat list below, so an unreferenced branch or loop
    # whose bodies are entirely pure was kept here and deleted by the Go, Java,
    # Rust and TypeScript tiers -- three tiers against four on the same
    # predicate. Measured directly, since no shipped path reaches DCE with that
    # shape today and the conformance suite therefore cannot see it:
    #
    #     go  HasSideEffect(pure if)   = false     zig hasSideEffect(pure if)   = true
    #     go  HasSideEffect(pure loop) = false     zig hasSideEffect(pure loop) = true
    #
    # Recursion is what makes retention both safe and precise: nested bindings
    # live inside the parent node rather than flattened into the method body, so
    # dropping an effectful ``if`` would take every nested ``assert`` /
    # ``check_preimage`` / ``add_output`` with it -- retention is all-or-nothing.
    # Mirrors ``packages/runar-compiler/src/optimizer/dce.ts``.
    if v.kind == "if":
        return any(has_side_effect(b.value) for b in (v.then or [])) or any(
            has_side_effect(b.value) for b in (v.else_ or [])
        )
    if v.kind == "loop":
        return any(has_side_effect(b.value) for b in (v.body or []))

    # A bin_op that can ABORT the script is not removable: purity is not
    # totality (spec/semantics.md §3.7). ``& | ^`` fail on operands of unequal
    # byte length, ``<< >>`` on a negative count, ``/ %`` on a zero divisor;
    # deleting the binding turns an abort into an accept (execution-fuzzer
    # seed 1351961626). Mirrors packages/runar-compiler/src/optimizer/dce.ts.
    if v.kind == "bin_op":
        return v.op in _PARTIAL_BIN_OPS

    return v.kind in (
        "assert",
        "update_prop",
        "check_preimage",
        "deserialize_state",
        "add_output",
        "add_raw_output",
        "add_data_output",
        "call",
        "method_call",
        # Opaque byte span -- DCE must never eliminate it.
        "raw_script",
    )
