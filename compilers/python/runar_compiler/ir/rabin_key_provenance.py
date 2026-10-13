"""N-205 (b) — F-286's verifyRabinSig key-provenance rule, and N-205 (a)'s rule
for writes to a key property, re-asserted on ``--ir`` input.

Port of packages/runar-compiler/src/ir/rabin-key-provenance.ts; read its header
for the full spec. In short: a ref is trusted when EVERY binding of that name
in the method (flattened pre-order) is a ``load_prop``, an integer
``load_const``, a ``load_const "@ref:<x>"`` with ``<x>`` trusted, a private
method's ``load_param`` that every ``method_call`` site (at least one) binds to
a trusted ref (least fixed point), or a result-less ``if`` whose two non-empty
arms each end in a trusted binding. KEY properties: the ``load_prop`` names a
verifyRabinSig 4th argument can come from, closed under trusted writes into a
key property. Method by method, first refusal wins: (1) an untrusted
verifyRabinSig 4th argument, then (2) an untrusted outside-the-constructor
write (``update_prop`` / ``add_output`` slot) of a mutable key property.
"""

from __future__ import annotations

from runar_compiler.frontend.validator import RABIN_PUBKEY_PROVENANCE_MESSAGE, rabin_key_write_message
from runar_compiler.ir.types import ANFBinding, ANFMethod, ANFProgram, ANFValue


def _flatten(bindings: list[ANFBinding] | None, out: list[ANFBinding]) -> None:
    for b in bindings or []:
        out.append(b)
        v = b.value
        for nested in (v.then, v.else_, v.body):
            if nested:
                _flatten(nested, out)


def _ref_target(v: ANFValue) -> str | None:
    s = v.const_string
    if isinstance(s, str) and s.startswith("@ref:"):
        return s[5:]
    return None


def assert_rabin_key_provenance(program: ANFProgram) -> None:
    """Raise the shared diagnostic for the first value the rule refuses."""
    methods = program.methods
    flat: dict[int, list[ANFBinding]] = {}
    by_name: dict[int, dict[str, list[ANFValue]]] = {}
    for m in methods:
        lst: list[ANFBinding] = []
        _flatten(m.body, lst)
        flat[id(m)] = lst
        names: dict[str, list[ANFValue]] = {}
        for b in lst:
            names.setdefault(b.name, []).append(b.value)
        by_name[id(m)] = names

    def is_private(m: ANFMethod) -> bool:
        return not m.is_public and m.name != "constructor"

    privates: dict[str, ANFMethod] = {}
    for m in methods:
        if is_private(m):
            privates[m.name] = m

    call_sites: dict[str, list[tuple[list[str], ANFMethod]]] = {n: [] for n in privates}
    for m in methods:
        for b in flat[id(m)]:
            v = b.value
            if v.kind == "method_call" and v.method in privates:
                call_sites[v.method].append((list(v.args or []), m))

    trusted_params: dict[str, set[int]] = {n: set() for n in privates}

    def param_index(m: ANFMethod, name: str | None) -> int:
        for i, p in enumerate(m.params):
            if p.name == name:
                return i
        return -1

    def is_trusted(ref: str, m: ANFMethod, visiting: set[str]) -> bool:
        values = by_name[id(m)].get(ref)
        if values is None or ref in visiting:
            return False
        visiting.add(ref)

        def one(v: ANFValue) -> bool:
            if v.kind == "load_prop":
                return True
            if v.kind == "load_const":
                if v.const_big_int is not None and v.const_bool is None:
                    return True
                target = _ref_target(v)
                return target is not None and is_trusted(target, m, visiting)
            if v.kind == "load_param":
                if not is_private(m):
                    return False
                idx = param_index(m, v.name)
                return idx >= 0 and idx in trusted_params[m.name]
            if v.kind == "if":
                if v.results:
                    return False
                then, els = v.then or [], v.else_ or []
                if not then or not els:
                    return False
                return is_trusted(then[-1].name, m, visiting) and is_trusted(els[-1].name, m, visiting)
            return False

        ok = all(one(v) for v in values)
        visiting.discard(ref)
        return ok

    changed = True
    while changed:
        changed = False
        for name, m in privates.items():
            sites = call_sites[name]
            if not sites:
                continue
            trusted = trusted_params[name]
            for i in range(len(m.params)):
                if i in trusted:
                    continue
                if all(i < len(args) and is_trusted(args[i], sm, set()) for args, sm in sites):
                    trusted.add(i)
                    changed = True

    def sources_of(ref: str, m: ANFMethod, out: set[str], visiting: set[str]) -> None:
        key = f"{m.name}\0{ref}"
        if key in visiting:
            return
        visiting.add(key)
        for v in by_name[id(m)].get(ref, []):
            if v.kind == "load_prop":
                if v.name is not None:
                    out.add(v.name)
            elif v.kind == "load_const":
                target = _ref_target(v)
                if target is not None:
                    sources_of(target, m, out, visiting)
            elif v.kind == "if":
                for arm in (v.then or [], v.else_ or []):
                    if arm:
                        sources_of(arm[-1].name, m, out, visiting)
            elif v.kind == "load_param" and is_private(m):
                idx = param_index(m, v.name)
                for args, sm in call_sites.get(m.name, []):
                    if 0 <= idx < len(args):
                        sources_of(args[idx], sm, out, visiting)

    def rabin_key_arg(v: ANFValue) -> str | None:
        if v.kind == "call" and v.func == "verifyRabinSig" and v.args is not None and len(v.args) >= 4:
            return v.args[3]
        return None

    key_props: set[str] = set()
    for m in methods:
        for b in flat[id(m)]:
            arg = rabin_key_arg(b.value)
            if arg is not None:
                sources_of(arg, m, key_props, set())

    mutable_props = [p.name for p in program.properties if not p.readonly]
    writes: list[tuple[str, str, ANFMethod]] = []
    for m in methods:
        if m.name == "constructor":
            continue
        for b in flat[id(m)]:
            v = b.value
            if v.kind == "update_prop" and v.name is not None and v.value_ref is not None:
                writes.append((v.name, v.value_ref, m))
            if v.kind == "add_output":
                for i, value in enumerate(v.state_values or []):
                    if i < len(mutable_props):
                        writes.append((mutable_props[i], value, m))

    grew = True
    while grew:
        before = len(key_props)
        for prop, value, m in writes:
            if prop in key_props and is_trusted(value, m, set()):
                sources_of(value, m, key_props, set())
        grew = len(key_props) != before

    mutable = set(mutable_props)
    for m in methods:
        for b in flat[id(m)]:
            arg = rabin_key_arg(b.value)
            if arg is not None and not is_trusted(arg, m, set()):
                raise ValueError(f"IR validation: method '{m.name}': {RABIN_PUBKEY_PROVENANCE_MESSAGE}")
        for prop, value, wm in writes:
            if wm is not m or prop not in key_props or prop not in mutable:
                continue
            if not is_trusted(value, m, set()):
                raise ValueError(f"IR validation: method '{m.name}': {rabin_key_write_message(prop)}")
