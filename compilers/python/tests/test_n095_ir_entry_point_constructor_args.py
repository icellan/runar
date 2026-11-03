"""N-095: the IR / direct-program entry points bake and validate constructor args.

Mirrors Rust F-103 and the TS reference ``compileFromANF``.

``compile_from_ir`` / ``compile_from_ir_bytes`` / ``compile_from_program`` took
no ``constructor_args`` at all, so a caller holding an ANF program (IR JSON or
an in-memory ``ANFProgram``) had no way to bake a readonly property: the
HashLock hash stayed an OP_0 placeholder slot. They now accept
``constructor_args`` and run the same unknown-key / F-101 type+width /
unbaked-readonly checks the source pipeline runs, before folding and the EC
optimizer.

Proves: HashLock compiled from IR bytes, an IR file and an in-memory program
with ``{hashValue: <32 bytes>}`` is byte-identical to the source compile with
the same args and carries no constructor slot; an unknown key, a width
mismatch and an unbaked referenced readonly property are refused on every IR
entry point; baking does not mutate the caller's program; with no args the
slotted artifact is unchanged.
Does not prove: the ``--ir`` JSON loader's own validation, or any CLI flag
(this tier's CLI has no constructor-args flag).
"""

from __future__ import annotations

import json
import textwrap

import pytest

from runar_compiler.compiler import (
    CompilationError,
    _serialize_anf_program,
    compile_from_ir,
    compile_from_ir_bytes,
    compile_from_program,
    compile_from_source,
    compile_source_to_ir,
)

HASH_LOCK_SOURCE = textwrap.dedent("""\
    from runar import SmartContract, ByteString, Sha256, public, assert_, sha256

    class HashLock(SmartContract):
        hash_value: Sha256

        def __init__(self, hash_value: Sha256):
            super().__init__(hash_value)
            self.hash_value = hash_value

        @public
        def unlock(self, preimage: ByteString):
            assert_(sha256(preimage) == self.hash_value)
""")

HASH = "aa" * 32


@pytest.fixture
def hash_lock(tmp_path):
    path = tmp_path / "HashLock.runar.py"
    path.write_text(HASH_LOCK_SOURCE, encoding="utf-8")
    program = compile_source_to_ir(str(path), disable_constant_folding=True)
    ir_bytes = json.dumps(_serialize_anf_program(program)).encode()
    ir_path = tmp_path / "HashLock.ir.json"
    ir_path.write_bytes(ir_bytes)
    return str(path), program, ir_bytes, str(ir_path)


def _entry_points(hash_lock):
    _, program, ir_bytes, ir_path = hash_lock
    return {
        "compile_from_ir_bytes": lambda args: compile_from_ir_bytes(ir_bytes, constructor_args=args),
        "compile_from_ir": lambda args: compile_from_ir(ir_path, constructor_args=args),
        "compile_from_program": lambda args: compile_from_program(
            program, disable_constant_folding=True, constructor_args=args),
    }


@pytest.mark.parametrize("entry", ["compile_from_ir_bytes", "compile_from_ir", "compile_from_program"])
def test_ir_entry_bakes_like_source_compile(hash_lock, entry):
    src_path = hash_lock[0]
    expected = compile_from_source(
        src_path, disable_constant_folding=True, constructor_args={"hashValue": HASH})
    got = _entry_points(hash_lock)[entry]({"hashValue": HASH})
    assert got.script == expected.script
    assert HASH in got.script
    assert got.constructor_slots == []


@pytest.mark.parametrize("entry", ["compile_from_ir_bytes", "compile_from_ir", "compile_from_program"])
def test_ir_entry_refuses_bad_args(hash_lock, entry):
    run = _entry_points(hash_lock)[entry]
    with pytest.raises(CompilationError, match="does not match any property"):
        run({"hashVal": HASH})  # typo
    with pytest.raises(CompilationError, match="hashValue"):
        run({"hashValue": "aabb"})  # wrong width for Sha256


@pytest.mark.parametrize("entry", ["compile_from_ir_bytes", "compile_from_ir", "compile_from_program"])
def test_ir_entry_refuses_unbaked_referenced_readonly(hash_lock, entry):
    run = _entry_points(hash_lock)[entry]
    with pytest.raises(CompilationError, match="hashValue"):
        run({"somethingElse": HASH})


def test_ir_entry_without_args_keeps_slot_and_does_not_mutate_program(hash_lock):
    _, program, ir_bytes, _ = hash_lock
    baked = compile_from_program(program, disable_constant_folding=True,
                                 constructor_args={"hashValue": HASH})
    assert baked.constructor_slots == []
    # The caller's program must not have been baked in place.
    assert all(p.initial_value is None for p in program.properties)
    plain = compile_from_ir_bytes(ir_bytes)
    assert len(plain.constructor_slots) == 1
    assert HASH not in plain.script
