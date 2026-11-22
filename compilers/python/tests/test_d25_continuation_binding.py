"""D25 -- the contract-level continuation binding (continuation_binding.py):
classification, the SINGLE default, the hidden spent-outpoint field, the
diagnostics, and the ``--ir`` check. Port of
packages/runar-compiler/src/__tests__/d25-continuation-binding.test.ts.

The executed twin-input theft lives in the SDK tests
(packages/runar-py/tests/test_d25_twin_input.py).
"""
from __future__ import annotations

import copy
import json

import pytest

from runar_compiler.compiler import (
    _serialize_anf_program,
    compile_from_ir_bytes,
    compile_from_source_str_with_result,
)
from runar_compiler.frontend.continuation_binding import TWIN_BINDING_FIELD

STATEFUL = """import { StatefulSmartContract, assert, checkSig, extractAmount, extractOutputHash, hash256 } from 'runar-lang';
import type { PubKey, Sig, Sha256 } from 'runar-lang';
"""


def counter(inc_directive: str = "", dec_directive: str = "") -> str:
    return f"""{STATEFUL}
class Counter extends StatefulSmartContract {{
  count: bigint;
  constructor(count: bigint) {{ super(count); this.count = count; }}
  {inc_directive}
  public increment() {{ this.count++; }}
  {dec_directive}
  public decrement() {{ assert(this.count > 0n); this.count--; }}
}}"""


MIXED = f"""{STATEFUL}
class MixedPot extends StatefulSmartContract {{
  count: bigint;
  constructor(count: bigint) {{ super(count); this.count = count; }}
  public increment() {{ this.count++; }}
  public bump() {{ this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }}
}}"""


def compile_src(src: str, name: str):
    return compile_from_source_str_with_result(src, f"{name}.runar.ts", disable_constant_folding=True)


def ok(src: str, name: str):
    r = compile_src(src, name)
    if not r.success:
        raise AssertionError("; ".join(d.message for d in r.diagnostics))
    return r


def abi_mode(r, method: str):
    return next(m for m in r.artifact.abi.methods if m.name == method).sig_hash_type


def state_names(r) -> list[str]:
    return [f.name for f in r.artifact.state_fields]


def walk(bindings, f) -> None:
    for b in bindings:
        f(b)
        v = b["value"]
        for k in ("then", "else", "body"):
            if isinstance(v.get(k), list):
                walk(v[k], f)


def anf_of(src: str, name: str) -> dict:
    return copy.deepcopy(_serialize_anf_program(ok(src, name).anf))


def compile_ir(program: dict):
    return compile_from_ir_bytes(json.dumps(program).encode("utf-8"))


# ---------------------------------------------------------------------------
# class 1
# ---------------------------------------------------------------------------

def test_class1_defaults_every_continuation_method_to_single_and_drops_change_params():
    r = ok(counter(), "Counter")
    assert abi_mode(r, "increment") == 0x43
    assert abi_mode(r, "decrement") == 0x43
    assert state_names(r) == ["count"]
    inc = next(m for m in r.artifact.abi.methods if m.name == "increment")
    assert [p.name for p in inc.params] == ["_newAmount", "txPreimage"]


def test_class1_maps_all_acp_to_single_acp():
    d = "/** @sighash ALL|ANYONECANPAY|FORKID */"
    assert abi_mode(ok(counter(d, d), "Counter"), "increment") == 0xC3


def test_class1_keeps_explicit_single_acp():
    d = "/** @sighash SINGLE|ANYONECANPAY|FORKID */"
    assert abi_mode(ok(counter(d), "Counter"), "increment") == 0xC3


def test_class1_refuses_explicit_all_sibling():
    r = compile_src(counter("", "/** @sighash ALL|FORKID */"), "Counter")
    assert not r.success
    assert any(
        d.severity == "error" and "method 'decrement': @sighash ALL|FORKID" in d.message
        for d in r.diagnostics
    )


def test_class1_terminal_method_keeps_all():
    src = f"""{STATEFUL}
class Box extends StatefulSmartContract {{
  count: bigint;
  readonly owner: PubKey;
  constructor(count: bigint, owner: PubKey) {{ super(count, owner); this.count = count; this.owner = owner; }}
  public bump() {{ this.count++; }}
  public close(sig: Sig) {{ assert(checkSig(sig, this.owner)); }}
}}"""
    r = ok(src, "Box")
    assert abi_mode(r, "bump") == 0x43
    assert abi_mode(r, "close") is None


# ---------------------------------------------------------------------------
# class 2
# ---------------------------------------------------------------------------

def test_class2_appends_zero_initialised_sha256_field_last_outside_ctor_abi():
    r = ok(MIXED, "MixedPot")
    assert state_names(r) == ["count", TWIN_BINDING_FIELD]
    assert [p.name for p in r.artifact.abi.constructor.params] == ["count"]
    prop = next(p for p in r.anf.properties if p.name == TWIN_BINDING_FIELD)
    assert prop.type == "Sha256"
    iv = prop.initial_value
    assert iv == "00" * 32 or iv == bytes(32)
    # Every method keeps ALL: no blending of SINGLE and the field.
    assert abi_mode(r, "increment") is None
    assert abi_mode(r, "bump") is None


def test_class2_writes_outpoint_hash_in_auto_continuation_and_appends_it_to_add_output():
    p = anf_of(MIXED, "MixedPot")
    inc = next(m for m in p["methods"] if m["name"] == "increment")
    writes: list[str] = []
    walk(inc["body"], lambda b: writes.append(b["value"]["name"]) if b["value"]["kind"] == "update_prop" else None)
    assert TWIN_BINDING_FIELD in writes
    bump = next(m for m in p["methods"] if m["name"] == "bump")
    outs: list[dict] = []
    walk(bump["body"], lambda b: outs.append(b) if b["value"]["kind"] == "add_output" else None)
    assert len(outs) == 1
    assert len(outs[0]["value"]["stateValues"]) == 2


def test_class2_mutate_only_reading_extract_output_hash_is_bound():
    src = f"""{STATEFUL}
class Peek extends StatefulSmartContract {{
  count: bigint;
  constructor(count: bigint) {{ super(count); this.count = count; }}
  public bump(h: Sha256) {{ assert(extractOutputHash(this.txPreimage) !== h); this.count++; }}
}}"""
    r = ok(src, "Peek")
    assert abi_mode(r, "bump") is None
    assert state_names(r) == ["count", TWIN_BINDING_FIELD]


def test_class2_field_name_is_reserved():
    src = f"""{STATEFUL}
class X extends StatefulSmartContract {{
  _spentOutpointHash: bigint;
  constructor(_spentOutpointHash: bigint) {{ super(_spentOutpointHash); this._spentOutpointHash = _spentOutpointHash; }}
  public bump() {{ this._spentOutpointHash++; }}
}}"""
    r = compile_src(src, "X")
    assert not r.success
    assert any("'_spentOutpointHash' is reserved" in d.message for d in r.diagnostics)


# ---------------------------------------------------------------------------
# class 3
# ---------------------------------------------------------------------------

def pot(body: str) -> str:
    return f"""{STATEFUL}
class Pot extends StatefulSmartContract {{
  count: bigint;
  readonly owner: PubKey;
  constructor(count: bigint, owner: PubKey) {{ super(count, owner); this.count = count; this.owner = owner; }}
  public bump(sig: Sig) {{ {body} }}
}}"""


def test_class3_warns_on_unsigned_add_output_extract_amount():
    r = ok(pot("this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot")
    w = [d for d in r.diagnostics if d.severity == "warning" and "twin-input aliasing" in d.message]
    assert len(w) == 1
    assert state_names(r) == ["count"]
    assert abi_mode(r, "bump") is None


def test_class3_follows_a_local_initialised_from_extract_amount():
    r = ok(pot("const v: bigint = extractAmount(this.txPreimage); this.addOutput(v, this.count + 1n);"), "Pot")
    assert any("twin-input aliasing" in d.message for d in r.diagnostics)


def test_class3_no_warning_when_method_checks_a_signature():
    r = ok(pot("assert(checkSig(sig, this.owner)); this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot")
    assert not any("twin-input aliasing" in d.message for d in r.diagnostics)


# ---------------------------------------------------------------------------
# --ir check
# ---------------------------------------------------------------------------

def test_ir_accepts_frontend_ir_of_every_class():
    compile_ir(anf_of(counter(), "Counter"))
    compile_ir(anf_of(MIXED, "MixedPot"))


def test_ir_refuses_mutate_only_program_whose_continuation_commits_under_all():
    p = anf_of(counter(), "Counter")
    m = next(x for x in p["methods"] if x["name"] == "decrement")
    m.pop("sigHashType", None)
    with pytest.raises(Exception, match="IR validation"):
        compile_ir(p)


def test_ir_refuses_mixed_program_without_binding_field():
    plain = anf_of(MIXED, "MixedPot")
    plain["properties"] = [x for x in plain["properties"] if x["name"] != TWIN_BINDING_FIELD]
    for m in plain["methods"]:
        drop: set[str] = set()

        def mark(b):
            v = b["value"]
            if v["kind"] == "update_prop" and v["name"] == TWIN_BINDING_FIELD:
                drop.add(b["name"])
            if v["kind"] == "add_output":
                drop.add(v["stateValues"].pop())

        walk(m["body"], mark)
        by_name: dict[str, dict] = {}
        walk(m["body"], lambda b: by_name.__setitem__(b["name"], b))
        for n in list(drop):
            v = by_name[n]["value"]
            src = v["value"] if v["kind"] == "update_prop" else n
            sha = by_name[src]["value"]
            eo = by_name[sha["args"][0]]["value"]
            drop.update({src, sha["args"][0], eo["args"][0]})
        m["body"] = [b for b in m["body"] if b["name"] not in drop]
    with pytest.raises(Exception, match="not bound to its input"):
        compile_ir(plain)


def test_ir_refuses_add_output_whose_last_state_value_is_not_the_outpoint_hash():
    p = anf_of(MIXED, "MixedPot")
    bump = next(m for m in p["methods"] if m["name"] == "bump")

    def swap(b):
        if b["value"]["kind"] == "add_output":
            b["value"]["stateValues"][1] = b["value"]["stateValues"][0]

    walk(bump["body"], swap)
    with pytest.raises(Exception, match="every add_output must carry"):
        compile_ir(p)
