"""N-265 -- the ``--ir`` path bypasses N-180's MAX_CALL_DEPTH bound, and
(outside Go's F-071, which was cycle-only) the recursion check entirely.

``load_ir`` never ran ``frontend/validator.py``'s recursion/call-depth check
(that only runs on the source path); ``validate_ir`` had no equivalent of
its own. Stack lowering (``codegen/stack.py``'s method_call inlining)
inlines every ``method_call`` to a private method by lowering its body in
place, with no cycle or depth guard, so a self/mutually-recursive method
recurses the host call stack until ``RecursionError``, and an acyclic chain
past MAX_CALL_DEPTH recurses it just as deep -- test_n180_call_depth_limit's
own module docstring says outright this path is unproven ("nor anything
about the --ir JSON path").

Proves: ``load_ir`` now refuses a chain one past MAX_CALL_DEPTH, naming the
first offending method in declaration order with the shared diagnostic,
accepts a chain right at the bound, refuses a 20000-link chain promptly (no
RecursionError, no multi-second hang), and refuses a direct/mutual cycle
with the shared recursion wording.

Does not prove: that the other six tiers' --ir loaders agree
(conformance/negatives/n265-ir-call-depth-parity.test.ts does); call graphs
other than a chain or a 2/3-node cycle; or that 128 is the right number
(N-180 already measured that).
"""

from __future__ import annotations

import json
import time

import pytest

from runar_compiler.frontend.input_limits import MAX_CALL_DEPTH
from runar_compiler.ir.loader import load_ir


def chain_ir(n: int) -> str:
    """verify(a) calls m0(a); m_i calls m_{i+1} for i < n; m_{n-1} returns its
    argument unchanged. Declaration order is m0..m(n-1) THEN verify, matching
    N-180's own chain fixture: at n=MAX_CALL_DEPTH only `verify` exceeds the
    bound, but at n=20000 `m0` is declared first and already exceeds it."""
    methods = []
    for i in range(n):
        if i == n - 1:
            body = [{"name": "t0", "value": {"kind": "load_param", "name": "x"}}]
        else:
            body = [
                {"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "x"}},
                {"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": f"m{i + 1}", "args": ["t1"]}},
            ]
        methods.append({"name": f"m{i}", "isPublic": False, "params": [{"name": "x", "type": "bigint"}], "body": body})
    methods.append({
        "name": "verify",
        "isPublic": True,
        "params": [{"name": "a", "type": "bigint"}],
        "body": [
            {"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
            {"name": "t1", "value": {"kind": "load_param", "name": "a"}},
            {"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": "m0", "args": ["t1"]}},
            {"name": "t3", "value": {"kind": "load_const", "value": 0}},
            {"name": "t4", "value": {"kind": "bin_op", "op": ">=", "left": "t2", "right": "t3"}},
            {"name": "t5", "value": {"kind": "assert", "value": "t4"}},
        ],
    })
    return json.dumps({"contractName": "Chain", "properties": [], "methods": methods})


def cycle_ir(private_methods: list[tuple[str, str | None]]) -> str:
    """unlock(x) calls private p(x); each (name, callee) in private_methods is
    either a terminal (callee=None, returns x) or forwards to callee."""
    methods = [{
        "name": "unlock",
        "isPublic": True,
        "params": [{"name": "x", "type": "bigint"}],
        "body": [
            {"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
            {"name": "t1", "value": {"kind": "load_param", "name": "x"}},
            {"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": "p", "args": ["t1"]}},
            {"name": "t3", "value": {"kind": "load_const", "value": 0}},
            {"name": "t4", "value": {"kind": "bin_op", "op": ">=", "left": "t2", "right": "t3"}},
            {"name": "t5", "value": {"kind": "assert", "value": "t4"}},
        ],
    }]
    for name, callee in private_methods:
        if callee is None:
            body = [{"name": "t0", "value": {"kind": "load_param", "name": "x"}}]
        else:
            body = [
                {"name": "t0", "value": {"kind": "load_const", "value": "@this"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "x"}},
                {"name": "t2", "value": {"kind": "method_call", "object": "t0", "method": callee, "args": ["t1"]}},
            ]
        methods.append({"name": name, "isPublic": False, "params": [{"name": "x", "type": "bigint"}], "body": body})
    return json.dumps({"contractName": "Rec", "properties": [], "methods": methods})


def test_chain_at_max_call_depth_compiles():
    load_ir(chain_ir(MAX_CALL_DEPTH))


def test_chain_one_past_max_call_depth_refused():
    with pytest.raises(ValueError) as exc:
        load_ir(chain_ir(MAX_CALL_DEPTH + 1))
    assert f"call depth of method 'verify' exceeds MAX_CALL_DEPTH (limit={MAX_CALL_DEPTH})" in str(exc.value)


def test_20000_link_chain_refused_promptly():
    start = time.monotonic()
    with pytest.raises(ValueError) as exc:
        load_ir(chain_ir(20000))
    assert f"call depth of method 'm0' exceeds MAX_CALL_DEPTH (limit={MAX_CALL_DEPTH})" in str(exc.value)
    assert time.monotonic() - start < 10, "refusal took too long"


def test_direct_self_recursion_refused():
    with pytest.raises(ValueError) as exc:
        load_ir(cycle_ir([("p", "p")]))
    msg = str(exc.value)
    assert "recursion detected" in msg
    assert "calls itself directly or indirectly" in msg
    assert "method 'p'" in msg


def test_mutual_recursion_refused():
    with pytest.raises(ValueError) as exc:
        load_ir(cycle_ir([("p", "q"), ("q", "p")]))
    msg = str(exc.value)
    assert "recursion detected" in msg
    assert "method 'p'" in msg or "method 'q'" in msg


def test_non_recursive_chain_still_loads():
    load_ir(cycle_ir([("p", "q"), ("q", "r"), ("r", None)]))
