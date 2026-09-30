"""F-086 — a name minted by the EC optimizer must never collide with a name the
method already uses.

The scalar-fusing rules (9, 10, 11) bind the folded scalar under a generated
name (``__ec_opt_N`` in this tier) just before the rewritten binding.
``_fresh_const_name`` never checked whether that name was taken. ANF is
single-assignment and stack lowering resolves a name to its shallowest slot,
so when ``__ec_opt_N`` is already a body binding or a method param the two
values alias. Reachable from ``--ir``, where names are attacker-chosen.
Pre-fix, ``__ec_opt_1 = 999; s = ecAdd(ecMulGen(2), ecMulGen(3));
assert(k == __ec_opt_1)`` compiled to a script that accepts k = 5 and rejects
the honest k = 999 (@bsv/sdk Spend.validate, strict v1 — F-086 remediation
log).

Proves: the minted name is fresh w.r.t. every binding (at any depth), param
and property; colliding programs compile to exactly the script of their
renamed twins; the no-collision name is unchanged.
Does not prove: anything about names minted by stack lowering (``_codePart``,
``__param_*``, ``__merge$*``).
"""
from __future__ import annotations

import json

import pytest

from runar_compiler.compiler import compile_from_ir_bytes
from runar_compiler.frontend import anf_optimize
from runar_compiler.frontend.anf_optimize import optimize_ec
from runar_compiler.ir.loader import load_ir


def _program_json(body_name: str | None, k_param: str) -> str:
    body = []
    if body_name:
        body.append({"name": body_name, "value": {"kind": "load_const", "value": 999}})
    body += [
        {"name": "t1", "value": {"kind": "load_const", "value": 2}},
        {"name": "t2", "value": {"kind": "call", "func": "ecMulGen", "args": ["t1"]}},
        {"name": "t3", "value": {"kind": "load_const", "value": 3}},
        {"name": "t4", "value": {"kind": "call", "func": "ecMulGen", "args": ["t3"]}},
        {"name": "s", "value": {"kind": "call", "func": "ecAdd", "args": ["t2", "t4"]}},
        {"name": "t5", "value": {"kind": "load_param", "name": "p"}},
        {"name": "t6", "value": {"kind": "bin_op", "op": "===", "left": "s", "right": "t5"}},
        {"name": "t7", "value": {"kind": "assert", "value": "t6"}},
        {"name": "t8", "value": {"kind": "load_param", "name": k_param}},
    ]
    rhs = body_name
    if not body_name:
        body.append({"name": "t9c", "value": {"kind": "load_const", "value": 999}})
        rhs = "t9c"
    body += [
        {"name": "t9", "value": {"kind": "bin_op", "op": "===", "left": "t8", "right": rhs}},
        {"name": "t10", "value": {"kind": "assert", "value": "t9"}},
    ]
    return json.dumps({
        "contractName": "EcOptCollide",
        "properties": [],
        "methods": [
            {"name": "constructor", "isPublic": False, "params": [],
             "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
            {"name": "unlock", "isPublic": True,
             "params": [{"name": "p", "type": "Point"}, {"name": k_param, "type": "bigint"}],
             "body": body},
        ],
    })


@pytest.fixture(autouse=True)
def _reset_counter(monkeypatch):
    # The counter is process-global; pin it so the first minted name is the
    # one the colliding programs below already use.
    monkeypatch.setattr(anf_optimize, "_fresh_counter", 0)


def _optimized_unlock(src: str):
    program = optimize_ec(load_ir(src))
    return next(m for m in program.methods if m.name == "unlock")


def _fused_scalar(method) -> int:
    i = next(i for i, b in enumerate(method.body) if b.name == "s")
    s = method.body[i].value
    assert s.kind == "call" and s.func == "ecMulGen"
    arg = s.args[0]
    assert arg not in {p.name for p in method.params}, f"fused scalar {arg} is a param name"
    prior = [b for b in method.body[:i] if b.name == arg]
    assert len(prior) == 1, f"fused scalar name {arg} bound {len(prior)} times"
    return prior[0].value.const_big_int


def _assert_single_assignment(method) -> None:
    names = [b.name for b in method.body]
    assert len(set(names)) == len(names), names
    assert not ({p.name for p in method.params} & set(names)), names


def test_no_collision_keeps_historical_name():
    m = _optimized_unlock(_program_json(None, "k"))
    assert any(b.name == "__ec_opt_1" for b in m.body)
    assert _fused_scalar(m) == 5


def test_preexisting_body_binding_is_not_shadowed():
    m = _optimized_unlock(_program_json("__ec_opt_1", "k"))
    _assert_single_assignment(m)
    assert _fused_scalar(m) == 5


def test_param_is_not_shadowed():
    m = _optimized_unlock(_program_json(None, "__ec_opt_1"))
    _assert_single_assignment(m)
    assert _fused_scalar(m) == 5


def test_colliding_programs_compile_like_their_renamed_twins(monkeypatch):
    def hex_of(src: str) -> str:
        monkeypatch.setattr(anf_optimize, "_fresh_counter", 0)
        return compile_from_ir_bytes(src.encode(), disable_constant_folding=True).script

    assert hex_of(_program_json("__ec_opt_1", "k")) == hex_of(_program_json("zz_unused", "k"))
    assert hex_of(_program_json(None, "__ec_opt_1")) == hex_of(_program_json(None, "zz"))
