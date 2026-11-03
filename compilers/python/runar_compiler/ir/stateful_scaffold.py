"""N-101: the scaffolding StatefulSmartContract lowering injects, re-derived
for ``--ir`` input.

``--ir`` skips the frontend, so a program labelled (or, per N-087, inferred)
StatefulSmartContract could omit or fake the scaffolding ANF lowering injects
into every public method and compile to an anyone-can-spend script: F-107's
attack body compiled to ``76767b8777``. For each public method this re-derives
what the frontend would inject (the TypeScript reference is
packages/runar-compiler/src/passes/stateful-scaffold.ts):

* prologue: ``assert(checkPreimage(txPreimage))``, the sighash-type assert and,
  when the contract has mutable properties, ``deserialize_state``;
* user code: free;
* continuation, when the method mutates state or declares outputs: the
  ``_newAmount`` floor (single-output form), the change output and the
  hashOutputs comparison over every output in order;

and reports, with the diagnostics all seven tiers share
(conformance/negatives/ir-stateful-scaffold-cases.json), the first of: (1) the
auto-injected parameters, (2) the prologue or (3) the continuation differ, or
(4) a scaffolding binding, or an output the continuation commits to, is bound
more than once or shares a property or parameter name.
"""

from __future__ import annotations

import json

from runar_compiler.ir.types import ANFBinding, ANFMethod, ANFProgram, ANFValue

SIGHASH_DEFAULT = 0x41
_STATE_OUTPUT_KINDS = frozenset({"add_output", "add_raw_output"})
_DATA_OUTPUT_KINDS = frozenset({"add_data_output"})


class _Emitter:
    def __init__(self, taken: set[str], counter: list[int]) -> None:
        self.taken = taken
        self.counter = counter
        self.out: list[ANFBinding] = []

    def emit(self, value: ANFValue) -> str:
        while True:
            name = f"$scaffold{self.counter[0]}"
            self.counter[0] += 1
            if name not in self.taken:
                break
        self.out.append(ANFBinding(name=name, value=value))
        return name

    def sub(self) -> "_Emitter":
        return _Emitter(self.taken, self.counter)


def _param(name: str) -> ANFValue:
    return ANFValue(kind="load_param", name=name)


def _call(func: str, *args: str) -> ANFValue:
    return ANFValue(kind="call", func=func, args=list(args))


def _bin(op: str, left: str, right: str, result_type: str | None = None) -> ANFValue:
    return ANFValue(kind="bin_op", op=op, left=left, right=right, result_type=result_type)


def _assert(ref: str) -> ANFValue:
    return ANFValue(kind="assert", value_ref=ref)


def _prologue(e: _Emitter, sighash_mode: int, has_mutable_state: bool) -> None:
    pre = e.emit(_param("txPreimage"))
    flag = None if sighash_mode == SIGHASH_DEFAULT else sighash_mode
    e.emit(_assert(e.emit(ANFValue(kind="check_preimage", preimage=pre, sighash_flag=flag))))
    p2 = e.emit(_param("txPreimage"))
    typ = e.emit(_call("extractSigHashType", p2))
    want = e.emit(ANFValue(kind="load_const", const_big_int=sighash_mode))
    e.emit(_assert(e.emit(_bin("===", typ, want))))
    if has_mutable_state:
        p3 = e.emit(_param("txPreimage"))
        e.emit(ANFValue(kind="deserialize_state", preimage=p3))


def _continuation(
    e: _Emitter, needs_change: bool, includes_change: bool,
    state_refs: list[str], data_refs: list[str],
) -> None:
    if not needs_change:
        return
    if not state_refs:
        p = e.emit(_param("txPreimage"))
        amount = e.emit(_call("extractAmount", p))
        new_amount = e.emit(_param("_newAmount"))
        e.emit(_assert(e.emit(_bin(">=", new_amount, amount))))
    # N-038: under a SIGHASH_SINGLE base no change segment exists.
    change: str | None = None
    if includes_change:
        pkh = e.emit(_param("_changePKH"))
        amt = e.emit(_param("_changeAmount"))
        zero = e.emit(ANFValue(kind="load_const", const_big_int=0))
        non_zero = e.emit(_bin("!==", amt, zero))
        then_e = e.sub()
        then_e.emit(_call("buildChangeOutput", pkh, amt))
        else_e = e.sub()
        else_e.emit(ANFValue(kind="load_const", const_string=""))
        change = e.emit(ANFValue(kind="if", cond=non_zero, then=then_e.out, else_=else_e.out))
    if state_refs:
        acc = state_refs[0]
        for r in state_refs[1:]:
            acc = e.emit(_call("cat", acc, r))
    else:
        script = e.emit(ANFValue(kind="get_state_script"))
        p = e.emit(_param("txPreimage"))
        new_amount = e.emit(_param("_newAmount"))
        acc = e.emit(_call("computeStateOutput", p, script, new_amount))
    for r in data_refs:
        acc = e.emit(_call("cat", acc, r))
    if change is not None:
        acc = e.emit(_call("cat", acc, change))
    digest = e.emit(_call("hash256", acc))
    p = e.emit(_param("txPreimage"))
    out_hash = e.emit(_call("extractOutputHash", p))
    eq = e.emit(_bin("===", digest, out_hash, "bytes"))
    e.emit(ANFValue(kind="assert", value_ref=eq, is_auto_injected_state_check=True))


def _nested(v: ANFValue) -> list[list[ANFBinding]]:
    return [n for n in (v.then, v.else_, v.body) if n]


def _contains(bindings: list[ANFBinding], kinds: frozenset[str]) -> bool:
    return any(
        b.value.kind in kinds or any(_contains(n, kinds) for n in _nested(b.value))
        for b in bindings
    )


def _shape(program: ANFProgram, method: ANFMethod) -> tuple[bool, bool, bool]:
    """The frontend's side-effect summary, read off the IR (update_prop is a
    state mutation, add_output / add_raw_output a state output,
    add_data_output a data output) at any depth and through method_calls to
    private methods."""
    privates = {
        m.name: m for m in program.methods if not m.is_public and m.name != "constructor"
    }
    effects = {"mutates": False, "state": False, "data": False}
    visited: set[str] = set()

    def walk(bindings: list[ANFBinding]) -> None:
        for b in bindings:
            v = b.value
            if v.kind == "update_prop":
                effects["mutates"] = True
            elif v.kind in _STATE_OUTPUT_KINDS:
                effects["state"] = True
            elif v.kind == "add_data_output":
                effects["data"] = True
            elif v.kind == "method_call":
                target = privates.get(v.method or "")
                if target is not None and target.name not in visited:
                    visited.add(target.name)
                    walk(target.body)
            for n in _nested(v):
                walk(n)

    walk(method.body)
    mutates, state, data = effects["mutates"], effects["state"], effects["data"]
    needs_change = mutates or state or data
    # N-038: a SIGHASH_SINGLE base commits no change output.
    mode = method.sighash_type if method.sighash_type is not None else SIGHASH_DEFAULT
    includes_change = needs_change and (mode & 0x1F) != 0x03
    return needs_change, includes_change, (mutates or data) and not state


def _describe(v: ANFValue) -> str:
    if v.kind == "load_param":
        return f"load_param {v.name}"
    if v.kind == "load_const":
        if v.const_string is not None:
            return f"load_const {json.dumps(v.const_string)}"
        return f"load_const {v.const_big_int}"
    if v.kind == "call":
        return f"call {v.func}"
    if v.kind == "bin_op":
        return f"bin_op {v.op}"
    return v.kind


def _const_int(v: ANFValue) -> int | None:
    if v.const_bool is not None or v.const_string is not None:
        return None
    if v.const_big_int is not None:
        return v.const_big_int
    return v.const_int


class _Matcher:
    def __init__(self) -> None:
        self.map: dict[str, str] = {}
        self.mapped: set[str] = set()

    def ref(self, e: str | None, a: str | None) -> bool:
        if e in self.map:
            return self.map[e] == a
        return e == a

    def binding(self, exp: ANFBinding, act: ANFBinding) -> bool:
        e, a = exp.value, act.value
        if e.kind != a.kind:
            return False
        k = e.kind
        if k == "load_param":
            ok = e.name == a.name
        elif k == "load_const":
            if e.const_string is not None:
                ok = a.const_string == e.const_string and a.const_bool is None
            else:
                ok = _const_int(a) == e.const_big_int
        elif k == "check_preimage":
            ok = self.ref(e.preimage, a.preimage) and (
                (e.sighash_flag or SIGHASH_DEFAULT) == (a.sighash_flag or SIGHASH_DEFAULT)
            )
        elif k == "assert":
            ok = self.ref(e.value_ref, a.value_ref)
        elif k == "call":
            ea, aa = e.args or [], a.args or []
            ok = e.func == a.func and len(ea) == len(aa) and all(
                self.ref(x, y) for x, y in zip(ea, aa)
            )
        elif k == "bin_op":
            ok = (
                e.op == a.op
                and self.ref(e.left, a.left)
                and self.ref(e.right, a.right)
                and (e.result_type or None) == (a.result_type or None)
            )
        elif k == "deserialize_state":
            ok = self.ref(e.preimage, a.preimage)
        elif k == "get_state_script":
            ok = True
        elif k == "if":
            ok = (
                self.ref(e.cond, a.cond)
                and not a.results
                and self.sequence(e.then or [], a.then or []) == -1
                and self.sequence(e.else_ or [], a.else_ or []) == -1
            )
        else:
            ok = False
        if not ok or act.name in self.mapped:
            return False
        self.map[exp.name] = act.name
        self.mapped.add(act.name)
        return True

    def sequence(self, exp: list[ANFBinding], act: list[ANFBinding]) -> int:
        """Index of the first binding that differs (a missing one included), or -1."""
        for i, e in enumerate(exp):
            if i >= len(act) or not self.binding(e, act[i]):
                return i
        return -1 if len(act) == len(exp) else len(exp)


def _collect_names(bindings: list[ANFBinding], counts: dict[str, int]) -> None:
    for b in bindings:
        counts[b.name] = counts.get(b.name, 0) + 1
        for r in b.value.results or []:
            counts[r] = counts.get(r, 0) + 1
        if b.value.kind == "loop" and b.value.iter_var:
            counts[b.value.iter_var] = counts.get(b.value.iter_var, 0) + 1
        for n in _nested(b.value):
            _collect_names(n, counts)


def _scaffold(method: str, detail: str) -> str:
    return (
        f"stateful method '{method}' does not carry the scaffolding "
        f"StatefulSmartContract lowering injects: {detail}"
    )


def stateful_scaffold_error(program: ANFProgram) -> str | None:
    """The first scaffolding divergence, without the ``IR validation: `` prefix
    ``load_ir`` adds, or ``None``."""
    has_mutable = any(not p.readonly for p in program.properties)
    props = {p.name for p in program.properties}
    for m in program.methods:
        if not m.is_public or m.name == "constructor":
            continue
        needs_change, includes_change, needs_new_amount = _shape(program, m)

        # (1) the parameters, contiguous and once each.
        required: list[tuple[str, str]] = []
        if includes_change:
            required += [("_changePKH", "Ripemd160"), ("_changeAmount", "bigint")]
        if needs_new_amount:
            required.append(("_newAmount", "bigint"))
        required.append(("txPreimage", "SigHashPreimage"))
        names = [p.name for p in m.params]
        start = names.index(required[0][0]) if required[0][0] in names else -1
        params_ok = start >= 0 and all(
            start + i < len(m.params)
            and m.params[start + i].name == n
            and m.params[start + i].type == t
            and names.count(n) == 1
            for i, (n, t) in enumerate(required)
        )
        if not params_ok:
            listed = ", ".join(f"{n}: {t}" for n, t in required)
            return (
                f"stateful method '{m.name}' must declare the auto-injected parameters "
                f"({listed}) contiguously and once each, as StatefulSmartContract lowering does"
            )

        counts: dict[str, int] = {}
        _collect_names(m.body, counts)
        taken = set(counts)
        counter = [0]
        match = _Matcher()

        # (2) the prologue.
        pro = _Emitter(taken, counter)
        _prologue(pro, m.sighash_type if m.sighash_type is not None else SIGHASH_DEFAULT, has_mutable)
        head = m.body[: len(pro.out)]
        i = match.sequence(pro.out, head)
        if i != -1:
            return _scaffold(m.name, f"prologue binding {i} must be {_describe(pro.out[i].value)}")

        # (3) the continuation, over the outputs the method's own top-level
        # bindings declare (an `if` counts once, as a state output when either
        # arm holds one, else as a data output), in order.
        rest = m.body[len(pro.out):]
        state_out: list[ANFBinding] = []
        data_out: list[ANFBinding] = []
        for b in rest:
            k = b.value.kind
            if k in _STATE_OUTPUT_KINDS:
                state_out.append(b)
            elif k == "add_data_output":
                data_out.append(b)
            elif k == "if":
                if any(_contains(n, _STATE_OUTPUT_KINDS) for n in _nested(b.value)):
                    state_out.append(b)
                elif any(_contains(n, _DATA_OUTPUT_KINDS) for n in _nested(b.value)):
                    data_out.append(b)
        tail = _Emitter(taken, counter)
        _continuation(tail, needs_change, includes_change, [b.name for b in state_out], [b.name for b in data_out])
        offset = len(rest) - len(tail.out)
        for i, e in enumerate(tail.out):
            if offset + i < 0 or not match.binding(e, rest[offset + i]):
                return _scaffold(m.name, f"continuation binding {i} must be {_describe(e.value)}")

        # (4) unique, unshadowed names for what the scaffolding binds or
        # commits to. A binding's own arms may reuse its name (an
        # output-carrying `if` is named after its arm's last binding).
        params = set(names)
        checked: list[ANFBinding] = []

        def preorder(bindings: list[ANFBinding]) -> None:
            for b in bindings:
                checked.append(b)
                for n in _nested(b.value):
                    preorder(n)

        preorder(head)
        if offset >= 0:
            preorder(rest[offset:])
        checked += state_out + data_out
        for b in checked:
            inner: dict[str, int] = {}
            for n in _nested(b.value):
                _collect_names(n, inner)
            if counts.get(b.name, 0) - inner.get(b.name, 0) != 1 or b.name in props or b.name in params:
                return (
                    f"stateful method '{m.name}' must bind '{b.name}' exactly once, under a name "
                    f"no property or parameter uses: the injected scaffolding binds it or the "
                    f"continuation commits to it"
                )
    return None
