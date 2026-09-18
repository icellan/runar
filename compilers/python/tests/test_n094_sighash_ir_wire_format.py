"""N-094 — the ``--emit-ir`` ANF wire format must carry ``@sighash`` losslessly.

``--emit-ir`` is a supported CLI mode and ANF is the declared conformance
boundary, so ANF emitted by this tier is fed back into ``--ir`` (here, and by
any other tier's loader) to produce a deployable locking script. A method
declaring ``/** @sighash SINGLE|FORKID */`` compiles the BIP-143 flag byte
0x43 into the OP_PUSH_TX binding; when the flag is dropped from (or misspelled
in) the emitted ANF the loader falls back to the default ALL|FORKID and the
binding silently becomes 0x41. Same script length, one byte different — a
covenant bound to the wrong sighash mode.

Every assertion here is on the ROUND-TRIPPED SCRIPT HEX, not on the presence of
a JSON key: the key is the mechanism, the byte is the harm.
"""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from runar_compiler import __main__ as cli_main
from runar_compiler.ir import types as ir_types

PYTHON_COMPILER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = PYTHON_COMPILER_DIR.parent.parent
ANF_SCHEMA = REPO_ROOT / "packages" / "runar-ir-schema" / "src" / "schemas" / "anf-ir.schema.json"
GO_CLI = REPO_ROOT / "compilers" / "go" / "runar-go"

#: SIGHASH_SINGLE | SIGHASH_FORKID.
SIGHASH_SINGLE_FORKID = 0x43

#: Stateless contract with a manual checkPreimage under a non-default mode.
SIGHASH_SRC = """\
import { SmartContract, SigHashPreimage, assert, checkPreimage } from "runar-lang";

class C extends SmartContract {
  readonly s: bigint;

  constructor(s: bigint) { super(s); this.s = s; }

  /** @sighash SINGLE|FORKID */
  public m(flag: bigint, pre: SigHashPreimage): void {
    if (flag > 0n) {
      assert(checkPreimage(pre));
    } else {
      assert(flag <= 0n);
    }
    assert(this.s >= 0n);
  }
}
"""

#: Control: the same contract with NO @sighash directive — default ALL|FORKID.
DEFAULT_SRC = SIGHASH_SRC.replace("  /** @sighash SINGLE|FORKID */\n", "")

#: Control: no checkPreimage at all — nothing for the flag to ride on.
NO_PREIMAGE_SRC = """\
import { SmartContract, assert } from "runar-lang";

class C extends SmartContract {
  readonly s: bigint;

  constructor(s: bigint) { super(s); this.s = s; }

  public m(flag: bigint): void {
    assert(flag > 0n);
    assert(this.s >= 0n);
  }
}
"""


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "runar_compiler", *args],
        cwd=str(PYTHON_COMPILER_DIR),
        capture_output=True,
        text=True,
        timeout=120,
        env=os.environ.copy(),
    )


def _round_trip(tmp_path: Path, src: str) -> tuple[str, str, dict]:
    """``--source --hex`` vs ``--emit-ir`` -> ``--ir --hex``.

    Returns ``(direct_hex, round_tripped_hex, emitted_anf)``.
    """
    source = tmp_path / "C.runar.ts"
    source.write_text(src)

    direct = _run(["--source", str(source), "--hex"])
    assert direct.returncode == 0, f"--source --hex failed: {direct.stderr}"

    emitted = _run(["--source", str(source), "--emit-ir"])
    assert emitted.returncode == 0, f"--emit-ir failed: {emitted.stderr}"

    ir_path = tmp_path / "ir.json"
    ir_path.write_text(emitted.stdout)

    rounded = _run(["--ir", str(ir_path), "--hex"])
    assert rounded.returncode == 0, f"--ir --hex failed: {rounded.stderr}"

    return direct.stdout.strip(), rounded.stdout.strip(), json.loads(emitted.stdout)


def _check_preimage_nodes(anf: object) -> list[dict]:
    found: list[dict] = []
    if isinstance(anf, dict):
        if anf.get("kind") == "check_preimage":
            found.append(anf)
        for v in anf.values():
            found.extend(_check_preimage_nodes(v))
    elif isinstance(anf, list):
        for v in anf:
            found.extend(_check_preimage_nodes(v))
    return found


# ---------------------------------------------------------------------------
# The harm: the round-tripped script byte
# ---------------------------------------------------------------------------


def test_sighash_survives_the_emit_ir_round_trip(tmp_path: Path) -> None:
    direct, rounded, _ = _round_trip(tmp_path, SIGHASH_SRC)
    assert direct
    assert direct == rounded, (
        "--emit-ir -> --ir changed the compiled script. The @sighash flag byte "
        f"did not survive the ANF wire format:\n  direct: {direct}\n  round : {rounded}"
    )


def test_round_tripped_script_still_commits_to_single_forkid(tmp_path: Path) -> None:
    single_dir = tmp_path / "single"
    single_dir.mkdir()
    default_dir = tmp_path / "default"
    default_dir.mkdir()
    direct, rounded, _ = _round_trip(single_dir, SIGHASH_SRC)
    default, _, _ = _round_trip(default_dir, DEFAULT_SRC)

    # Same length, one byte apart — which is exactly why the equality assertion
    # above is load-bearing and a length check would not be.
    assert len(default) == len(direct)
    assert default != direct, "expected @sighash SINGLE|FORKID to change the compiled script"
    assert default != rounded, (
        "the round-tripped script silently downgraded to the DEFAULT sighash mode"
    )


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def test_control_default_mode_round_trips_byte_identically(tmp_path: Path) -> None:
    direct, rounded, anf = _round_trip(tmp_path, DEFAULT_SRC)
    assert direct == rounded, "default-sighash contract no longer round-trips"
    for node in _check_preimage_nodes(anf):
        assert "sighashFlag" not in node, (
            "default mode must omit sighashFlag so pre-existing goldens stay byte-identical"
        )


def test_control_contract_without_check_preimage_round_trips(tmp_path: Path) -> None:
    direct, rounded, anf = _round_trip(tmp_path, NO_PREIMAGE_SRC)
    assert direct == rounded, "contract without checkPreimage no longer round-trips"
    assert _check_preimage_nodes(anf) == []


# ---------------------------------------------------------------------------
# Wire-format shape (the mechanism behind the byte)
# ---------------------------------------------------------------------------


def test_check_preimage_carries_camelcase_sighash_flag(tmp_path: Path) -> None:
    _, _, anf = _round_trip(tmp_path, SIGHASH_SRC)
    nodes = _check_preimage_nodes(anf)
    assert len(nodes) == 1, "expected exactly one check_preimage node"
    node = nodes[0]

    assert "sighash_flag" not in node, (
        "snake_case sighash_flag is not the wire spelling; Go/Zig/Rust/Java read sighashFlag"
    )
    assert node.get("sighashFlag") == SIGHASH_SINGLE_FORKID, (
        f"check_preimage lost the declared @sighash mode: {node!r}"
    )


def test_no_method_carries_a_stray_sighash_type(tmp_path: Path) -> None:
    _, _, anf = _round_trip(tmp_path, SIGHASH_SRC)
    for method in anf["methods"]:
        for key in ("sighash_type", "sighashType"):
            assert key not in method, (
                f"method {method['name']} leaks the in-memory sighash_type carrier "
                "into the ANF wire format"
            )


# ---------------------------------------------------------------------------
# Cross-tier: the reported reproduction. Go loads our ANF.
# ---------------------------------------------------------------------------


def test_go_compiles_our_anf_to_the_same_script(tmp_path: Path) -> None:
    if not (GO_CLI.exists() and os.access(GO_CLI, os.X_OK)):
        pytest.skip(f"go compiler binary not built at {GO_CLI}")

    source = tmp_path / "C.runar.ts"
    source.write_text(SIGHASH_SRC)

    go_direct = subprocess.run(
        [str(GO_CLI), "--source", str(source), "--hex"],
        capture_output=True, text=True, timeout=120,
    )
    assert go_direct.returncode == 0, f"go --source --hex failed: {go_direct.stderr}"

    emitted = _run(["--source", str(source), "--emit-ir"])
    assert emitted.returncode == 0, f"--emit-ir failed: {emitted.stderr}"
    ir_path = tmp_path / "ir.json"
    ir_path.write_text(emitted.stdout)

    go_round = subprocess.run(
        [str(GO_CLI), "--ir", str(ir_path), "--hex"],
        capture_output=True, text=True, timeout=120,
    )
    assert go_round.returncode == 0, f"go --ir --hex failed: {go_round.stderr}"

    assert go_direct.stdout.strip() == go_round.stdout.strip(), (
        "Go compiled a DIFFERENT script from our ANF than from the same source"
    )


# ---------------------------------------------------------------------------
# Lockstep guard — the class of defect, not this instance.
#
# The wire names the ANF JSON may use are fixed by the cross-tier JSON Schema in
# packages/runar-ir-schema. Every field an ANF node type declares must therefore
# either (a) serialize to a key that schema knows, and actually appear in the
# serializer's output, or (b) be listed in the serializer's documented exclusion
# set. A field that is neither is a field the serializer silently drops or
# misspells — exactly what happened to sighash_flag. The field list is read off
# the TYPE, so this fires the moment the type gains a field the serializer does
# not handle.
# ---------------------------------------------------------------------------


def _schema_wire_keys() -> set[str]:
    schema = json.loads(ANF_SCHEMA.read_text())
    keys = set(schema["properties"])
    for definition in schema["$defs"].values():
        if isinstance(definition, dict) and isinstance(definition.get("properties"), dict):
            keys |= set(definition["properties"])
    return keys


def _sentinel(name: str, kind: str) -> object:
    if name == "kind":
        return kind
    if name in {
        "then", "else_", "body", "args", "results", "state_values", "elements",
        "params", "properties", "methods",
    }:
        return []
    # N-095: this one must be NON-empty. The emitter skips an empty chain (as
    # Go's `omitempty` and Rust's `skip_serializing_if` do), so an `[]`
    # sentinel would make the "field reaches the wire" half of this guard
    # vacuous — exactly the blind spot that let three tiers spell the key three
    # different ways.
    if name == "synthetic_array_chain":
        return [{"base": "grid", "index": 0, "length": 2}]
    if name in {"count", "start", "step", "in_arity", "out_arity", "sighash_flag",
                "sighash_type", "line", "column"}:
        return 1
    if name in {"readonly", "is_public", "is_auto_injected_state_check", "preserve"}:
        return True
    if name == "value":
        return ir_types.ANFValue(kind="get_state_script")
    if name == "source_loc":
        return ir_types.SourceLocation()
    if name == "raw_value":
        return '"x"'
    return "x"


def _assert_fields_accounted_for(node_type: type, label: str, wire_keys: set[str]) -> None:
    fields = [f.name for f in dataclasses.fields(node_type)]

    # A few fields are emitted only for one `kind` (isAutoInjectedStateCheck
    # rides on `assert`, sighashFlag on `check_preimage`), so serialize the
    # fully-populated node once per discriminator and union the wire keys.
    emitted: set[str] = set()
    for kind in ("assert", "check_preimage"):
        node = node_type(**{name: _sentinel(name, kind) for name in fields})
        out = cli_main._anf_to_camel_dict(node)
        assert isinstance(out, dict)
        emitted |= set(out)

    for name in fields:
        if name in cli_main._IR_EXCLUDED_FIELDS:
            continue
        key = cli_main._snake_key(name)
        assert key in wire_keys, (
            f'{label}.{name} serializes to "{key}", which the cross-tier ANF JSON Schema '
            "does not accept. Fix the wire name, or exclude the field."
        )
        assert key in emitted, (
            f'{label}.{name} never reaches the emitted ANF (expected key "{key}"). '
            "Fields dropped here vanish silently: the Go loader ignores unknown keys."
        )


def test_every_anf_field_is_either_emitted_or_explicitly_excluded() -> None:
    wire_keys = _schema_wire_keys()

    declared = {f.name for f in dataclasses.fields(ir_types.ANFValue)}
    assert "sighash_flag" in declared, "ANFValue no longer declares sighash_flag"

    for node_type, label in (
        (ir_types.ANFValue, "ANFValue"),
        (ir_types.ANFProgram, "ANFProgram"),
        (ir_types.ANFProperty, "ANFProperty"),
        (ir_types.ANFMethod, "ANFMethod"),
        (ir_types.ANFParam, "ANFParam"),
        (ir_types.ANFBinding, "ANFBinding"),
    ):
        _assert_fields_accounted_for(node_type, label, wire_keys)
