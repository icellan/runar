"""F-038 / F-065 / F-066 / F-070 / F-088 -- ``--emit-ir`` -> ``--ir`` is lossless.

``parent_class`` and a method's ``sighash_type`` were in-memory carriers only
(``_IR_EXCLUDED_FIELDS``), so a second process compiling the emitted IR with
``--ir`` produced the same script but an artifact with no ``parentClass`` and
no ``abi.methods[].sigHashType``. The SDK reads both to sign (issue-#44
subscript trim; the preimage sighash mode), so the round-tripped artifact
drove it into spends the script rejects.

What this proves: in this tier, for a stateful FixedArray contract, a
stateless contract, an UnsafeSmartContract and a ``@sighash SINGLE|FORKID``
method, the emitted IR carries ``parentClass`` / ``sigHashType`` and the
``--ir`` artifact equals the ``--source`` artifact on script, parentClass, abi
and stateFields; the artifact-embedded ANF agrees with ``--emit-ir`` on those
keys; and the loader refuses a malformed value of either key with the shared
diagnostic.
What it does NOT prove: the other six tiers (conformance/ir-roundtrip does),
or that the SDK then spends (also conformance/ir-roundtrip).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from runar_compiler.ir.loader import load_ir

PKG_ROOT = Path(__file__).resolve().parents[1]

STATEFUL_FIXED_ARRAY = """from runar import (
    StatefulSmartContract, Bigint, FixedArray,
    public, assert_,
)


class ArrayWrite(StatefulSmartContract):
    table: FixedArray[Bigint, 4] = [0, 0, 0, 0]

    def __init__(self):
        super().__init__()

    @public
    def bump(self, i: Bigint):
        self.table[i] = self.table[i] + 1
        assert_(True)
"""

STATELESS = """from runar import SmartContract, Bigint, public, assert_


class Trail(SmartContract):
    k: Bigint

    def __init__(self, k: Bigint):
        super().__init__(k)
        self.k = k

    @public
    def unlock(self, n: Bigint):
        assert_(n == self.k)
"""

UNSAFE = """from runar import UnsafeSmartContract, public, asm


class Anyone(UnsafeSmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self):
        asm("51", 0, 1)
"""

SIGHASH_SINGLE = """import { SmartContract, PubKey, Sig, assert, checkSig } from 'runar-lang';

class SighashSingle extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  /** @sighash SINGLE|FORKID */
  public unlock(sig: Sig): void {
    assert(checkSig(sig, this.owner));
  }
}
"""


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "runar_compiler", *args],
        cwd=str(PKG_ROOT),
        capture_output=True,
        text=True,
    )


def _compile(tmp_path: Path, file_name: str, source: str) -> tuple[dict, dict, dict]:
    """Return (direct_artifact, emitted_ir, roundtrip_artifact)."""
    src = tmp_path / file_name
    src.write_text(source)

    direct_out = tmp_path / f"{file_name}.direct.json"
    res = _run("--source", str(src), "--output", str(direct_out))
    assert res.returncode == 0, res.stderr

    res = _run("--source", str(src), "--emit-ir")
    assert res.returncode == 0, res.stderr
    ir_out = tmp_path / f"{file_name}.ir.json"
    ir_out.write_text(res.stdout)

    rt_out = tmp_path / f"{file_name}.roundtrip.json"
    res = _run("--ir", str(ir_out), "--output", str(rt_out))
    assert res.returncode == 0, res.stderr

    return (
        json.loads(direct_out.read_text()),
        json.loads(ir_out.read_text()),
        json.loads(rt_out.read_text()),
    )


@pytest.mark.parametrize(
    "file_name,source,parent_class",
    [
        ("ArrayWrite.runar.py", STATEFUL_FIXED_ARRAY, "StatefulSmartContract"),
        ("Trail.runar.py", STATELESS, "SmartContract"),
        ("Anyone.runar.py", UNSAFE, "UnsafeSmartContract"),
        ("SighashSingle.runar.ts", SIGHASH_SINGLE, "SmartContract"),
    ],
    ids=["stateful-fixed-array", "stateless", "unsafe", "sighash-single"],
)
def test_round_trip_artifact_matches_direct(tmp_path, file_name, source, parent_class):
    direct, ir, roundtrip = _compile(tmp_path, file_name, source)

    assert ir.get("parentClass") == parent_class
    assert direct.get("parentClass") == parent_class
    assert roundtrip["script"] == direct["script"]
    assert roundtrip.get("parentClass") == direct.get("parentClass")
    assert roundtrip["abi"] == direct["abi"]
    assert roundtrip.get("stateFields") == direct.get("stateFields")


def test_sighash_rides_on_the_emitted_method(tmp_path):
    direct, ir, roundtrip = _compile(tmp_path, "SighashSingle.runar.ts", SIGHASH_SINGLE)
    by_name = {m["name"]: m for m in ir["methods"]}
    assert by_name["unlock"].get("sigHashType") == 0x43
    # Default-mode methods carry no key (keeps directive-free ANF unchanged).
    assert "sigHashType" not in by_name["constructor"]
    assert direct["abi"]["methods"][0]["sigHashType"] == 0x43
    assert roundtrip["abi"]["methods"][0].get("sigHashType") == 0x43


def test_artifact_embedded_anf_agrees_with_emit_ir(tmp_path):
    """compiler.py's ``_serialize_anf_program`` and ``--emit-ir`` carry the same keys."""
    from runar_compiler.compiler import _serialize_anf_program, compile_source_to_ir

    src = tmp_path / "ArrayWrite.runar.py"
    src.write_text(STATEFUL_FIXED_ARRAY)
    embedded = _serialize_anf_program(compile_source_to_ir(str(src)))
    _, emitted, _ = _compile(tmp_path, "ArrayWrite.runar.py", STATEFUL_FIXED_ARRAY)
    assert embedded["parentClass"] == emitted["parentClass"] == "StatefulSmartContract"
    assert [p.get("syntheticArrayChain") for p in embedded["properties"]] == [
        p.get("syntheticArrayChain") for p in emitted["properties"]
    ]
    assert any(p.get("syntheticArrayChain") for p in embedded["properties"])


_CONTROL = {
    "contractName": "X",
    "properties": [{"name": "pk", "type": "PubKey", "readonly": True}],
    "methods": [{
        "name": "unlock", "isPublic": True,
        "params": [{"name": "sig", "type": "Sig"}],
        "body": [
            {"name": "t0", "value": {"kind": "load_param", "name": "sig"}},
            {"name": "t1", "value": {"kind": "load_prop", "name": "pk"}},
            {"name": "t2", "value": {"kind": "call", "func": "checkSig", "args": ["t0", "t1"]}},
            {"name": "t3", "value": {"kind": "assert", "value": "t2"}},
        ],
    }],
}


def _with(program_extra: dict, method_extra: dict) -> str:
    d = json.loads(json.dumps(_CONTROL))
    d.update(program_extra)
    d["methods"][0].update(method_extra)
    return json.dumps(d)


def test_loader_keeps_both_keys():
    # N-101: a StatefulSmartContract label would now also demand the injected
    # scaffolding, which this stateless control does not carry; a non-default
    # label still proves the key survives the loader.
    program = load_ir(_with({"parentClass": "UnsafeSmartContract"}, {"sigHashType": 0xC3}))
    assert program.parent_class == "UnsafeSmartContract"
    assert program.methods[0].sighash_type == 0xC3


@pytest.mark.parametrize(
    "program_extra,method_extra,error",
    [
        ({"parentClass": 7}, {},
         "IR validation: parentClass must be a string, got number"),
        ({"parentClass": "Contract"}, {},
         "IR validation: parentClass must be one of SmartContract, StatefulSmartContract, "
         "UnsafeSmartContract, got Contract"),
        ({}, {"sigHashType": "0x43"},
         "IR validation: methods[0].sigHashType must be an integer, got string"),
        ({}, {"sigHashType": True},
         "IR validation: methods[0].sigHashType must be an integer, got boolean"),
        ({}, {"sigHashType": 3},
         "IR validation: methods[0].sigHashType must be one of 65, 66, 67, 193, 194, 195, got 3"),
    ],
    ids=["parent-class-number", "parent-class-unknown", "sighash-string", "sighash-bool",
         "sighash-no-forkid"],
)
def test_loader_refuses_malformed_values(program_extra, method_extra, error):
    with pytest.raises(ValueError) as exc:
        load_ir(_with(program_extra, method_extra))
    assert str(exc.value) == error
