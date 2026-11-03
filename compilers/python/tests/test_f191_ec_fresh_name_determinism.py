"""F-191 — the EC optimizer's fresh names must be a function of the program alone.

The scalar-fusing rules (9, 10, 11) bind the folded scalar under a newly minted
name. That name used to come from a module-global ``_fresh_counter`` that was
never reset, so compiling the identical source twice in one Python process gave
``__ec_opt_1`` the first time and ``__ec_opt_2`` the second: the optimized ANF
(and ``--emit-ir`` output) depended on whatever the process had compiled before.

The fix derives the name the way the TypeScript reference does
(``freshName(`${binding.name}_k`, usedNames)`` in
``packages/runar-compiler/src/optimizer/anf-ec.ts``): ``<binding>_k``, else the
first unused ``<binding>_k_<i>`` against the method's used names.

Proves: compiling the same Rule-10 source twice in one process yields
byte-identical serialized ANF; the minted name is ``<binding>_k`` as in TS; and a
collision with an existing name picks ``<binding>_k_1`` (TS ``freshName``).
Does not prove: script-byte effects (binding names never reach the hex; the
N-028 / F-086 suites pin the bytes), nor naming in any other tier.
"""
from __future__ import annotations

import json
from pathlib import Path

from runar_compiler.compiler import _serialize_anf_program, compile_source_to_ir
from runar_compiler.frontend.anf_optimize import optimize_ec
from runar_compiler.ir.loader import load_ir


EC_OPT_SOURCE = """\
import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';

class EcOpt extends SmartContract {
    constructor() {
        super();
    }

    public spend(a: bigint) {
        assert(ecOnCurve(ecAdd(ecMulGen(2n), ecMulGen(3n))));
    }
}
"""


def _ir_json(path: Path, disable_constant_folding: bool) -> str:
    program = compile_source_to_ir(str(path), disable_constant_folding=disable_constant_folding)
    return json.dumps(_serialize_anf_program(program), sort_keys=True)


def test_same_source_twice_in_one_process_gives_identical_anf(tmp_path):
    src = tmp_path / "EcOpt.runar.ts"
    src.write_text(EC_OPT_SOURCE, encoding="utf-8")
    for fold_off in (True, False):
        first = _ir_json(src, fold_off)
        second = _ir_json(src, fold_off)
        third = _ir_json(src, fold_off)
        assert first == second == third, (
            f"optimized ANF differs between identical compilations "
            f"(disable_constant_folding={fold_off})"
        )


def _rule10_program(extra_name: str | None) -> str:
    body = []
    if extra_name:
        body.append({"name": extra_name, "value": {"kind": "load_const", "value": 999}})
    body += [
        {"name": "t1", "value": {"kind": "load_const", "value": 2}},
        {"name": "t2", "value": {"kind": "call", "func": "ecMulGen", "args": ["t1"]}},
        {"name": "t3", "value": {"kind": "load_const", "value": 3}},
        {"name": "t4", "value": {"kind": "call", "func": "ecMulGen", "args": ["t3"]}},
        {"name": "s", "value": {"kind": "call", "func": "ecAdd", "args": ["t2", "t4"]}},
        {"name": "t5", "value": {"kind": "call", "func": "ecOnCurve", "args": ["s"]}},
        {"name": "t6", "value": {"kind": "assert", "value": "t5"}},
    ]
    if extra_name:
        body += [
            {"name": "t7", "value": {"kind": "load_const", "value": 999}},
            {"name": "t8", "value": {"kind": "bin_op", "op": "===", "left": extra_name, "right": "t7"}},
            {"name": "t9", "value": {"kind": "assert", "value": "t8"}},
        ]
    return json.dumps({
        "contractName": "EcOpt",
        "properties": [],
        "methods": [
            {"name": "constructor", "isPublic": False, "params": [],
             "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
            {"name": "spend", "isPublic": True, "params": [], "body": body},
        ],
    })


def _fused_scalar_name(src: str) -> str:
    m = next(m for m in optimize_ec(load_ir(src)).methods if m.name == "spend")
    s = next(b for b in m.body if b.name == "s")
    assert s.value.kind == "call" and s.value.func == "ecMulGen"
    return s.value.args[0]


def test_minted_name_follows_ts_fresh_name():
    # TS anf-ec.ts Rule 10: freshName(`${binding.name}_k`, usedNames).
    assert _fused_scalar_name(_rule10_program(None)) == "s_k"
    # Repeating it must not drift (the old counter would give the next N).
    assert _fused_scalar_name(_rule10_program(None)) == "s_k"


def test_minted_name_skips_a_used_name_like_ts():
    assert _fused_scalar_name(_rule10_program("s_k")) == "s_k_1"
