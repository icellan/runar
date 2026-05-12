"""Op-shape parity tests for the Python ``hash160`` and ``hash256`` builtins.

Both lower through the simple table-driven ``BUILTIN_OPCODES`` mapping in
``stack.py:116``:

  * ``hash160``  -> [OP_HASH160]   (RIPEMD160(SHA256(x)) -- 20 bytes out)
  * ``hash256``  -> [OP_HASH256]   (SHA256(SHA256(x))    -- 32 bytes out)

The table also covers ``sha256`` and ``ripemd160`` for completeness; their
opcodes are checked here in the same shape so a future regression that
swaps two entries in the table fails immediately.

Tests drive the lowering with a minimal hand-built ANF program:
``r = builtin(p0); assert(r);`` -- mirrors the pattern in
``test_math_builtins.py``.
"""

from __future__ import annotations

import pytest

from runar_compiler.codegen.stack import (
    StackMethod,
    StackOp,
    lower_to_stack,
)
from runar_compiler.codegen.emit import emit_method
from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFParam,
    ANFProgram,
    ANFValue,
)


# ---------------------------------------------------------------------------
# Minimal ANF program builder (mirrors test_math_builtins.py)
# ---------------------------------------------------------------------------

def _build_call_program(func_name: str, arg_type: str = "ByteString") -> ANFProgram:
    """Return an ANF program with a single ``unlock`` method::

        r = func_name(p0)
        assert(r)

    p0 is typed as `arg_type` (default ByteString -- the natural input for
    hashes -- though hash builtins accept any byte-typed value).
    """
    body: list[ANFBinding] = [
        ANFBinding(name="a0", value=ANFValue(kind="load_param", name="p0")),
        ANFBinding(
            name="r",
            value=ANFValue(kind="call", func=func_name, args=["a0"]),
        ),
        ANFBinding(name="_assert", value=ANFValue(kind="assert", value_ref="r")),
    ]
    method = ANFMethod(
        name="unlock",
        params=[ANFParam(name="p0", type=arg_type)],
        body=body,
        is_public=True,
    )
    return ANFProgram(contract_name="HashProbe", properties=[], methods=[method])


def _unlock_ops(func_name: str, arg_type: str = "ByteString") -> list[StackOp]:
    program = _build_call_program(func_name, arg_type)
    methods = lower_to_stack(program)
    unlock = next(m for m in methods if m.name == "unlock")
    return unlock.ops


def _is_opcode(op: StackOp, code: str) -> bool:
    return op.op == "opcode" and op.code == code


# ---------------------------------------------------------------------------
# Per-builtin opcode goldens
# ---------------------------------------------------------------------------

class TestHash160:
    def test_emits_exactly_one_op_hash160(self):
        ops = _unlock_ops("hash160")
        assert len(ops) == 1, (
            f"hash160 must emit exactly 1 op; got {len(ops)}"
        )
        assert _is_opcode(ops[0], "OP_HASH160"), (
            f"hash160 must emit OP_HASH160; got {ops[0]!r}"
        )

    def test_does_not_emit_op_hash256(self):
        ops = _unlock_ops("hash160")
        assert not any(_is_opcode(op, "OP_HASH256") for op in ops)

    def test_does_not_emit_op_sha256(self):
        """OP_HASH160 is RIPEMD160(SHA256(x)) but is implemented as a SINGLE
        opcode -- no manual SHA256 + RIPEMD160 expansion.
        """
        ops = _unlock_ops("hash160")
        assert not any(_is_opcode(op, "OP_SHA256") for op in ops)
        assert not any(_is_opcode(op, "OP_RIPEMD160") for op in ops)

    def test_emits_to_hex(self):
        """End-to-end: the lowered op must encode to the canonical 1-byte
        hex 'a9' (OP_HASH160 = 0xa9).
        """
        ops = _unlock_ops("hash160")
        method = StackMethod(name="unlock", ops=list(ops), max_stack_depth=0)
        res = emit_method(method)
        assert res.script_hex == "a9", (
            f"hash160 hex must be 'a9'; got {res.script_hex!r}"
        )


class TestHash256:
    def test_emits_exactly_one_op_hash256(self):
        ops = _unlock_ops("hash256")
        assert len(ops) == 1, (
            f"hash256 must emit exactly 1 op; got {len(ops)}"
        )
        assert _is_opcode(ops[0], "OP_HASH256"), (
            f"hash256 must emit OP_HASH256; got {ops[0]!r}"
        )

    def test_does_not_emit_op_hash160(self):
        ops = _unlock_ops("hash256")
        assert not any(_is_opcode(op, "OP_HASH160") for op in ops)

    def test_emits_to_hex(self):
        """OP_HASH256 = 0xaa."""
        ops = _unlock_ops("hash256")
        method = StackMethod(name="unlock", ops=list(ops), max_stack_depth=0)
        res = emit_method(method)
        assert res.script_hex == "aa", (
            f"hash256 hex must be 'aa'; got {res.script_hex!r}"
        )


class TestSha256:
    def test_emits_exactly_one_op_sha256(self):
        """sha256 lowers to a single OP_SHA256 (NOT the dedicated
        sha256_compress/finalize emitters -- those are for partial-hash flows).
        """
        ops = _unlock_ops("sha256")
        assert len(ops) == 1
        assert _is_opcode(ops[0], "OP_SHA256")

    def test_emits_to_hex(self):
        """OP_SHA256 = 0xa8."""
        ops = _unlock_ops("sha256")
        method = StackMethod(name="unlock", ops=list(ops), max_stack_depth=0)
        res = emit_method(method)
        assert res.script_hex == "a8"


class TestRipemd160:
    def test_emits_exactly_one_op_ripemd160(self):
        ops = _unlock_ops("ripemd160")
        assert len(ops) == 1
        assert _is_opcode(ops[0], "OP_RIPEMD160")

    def test_emits_to_hex(self):
        """OP_RIPEMD160 = 0xa6."""
        ops = _unlock_ops("ripemd160")
        method = StackMethod(name="unlock", ops=list(ops), max_stack_depth=0)
        res = emit_method(method)
        assert res.script_hex == "a6"


# ---------------------------------------------------------------------------
# Cross-builtin: ensure the four hashes don't accidentally share an opcode
# (a copy-paste swap in BUILTIN_OPCODES would otherwise go undetected).
# ---------------------------------------------------------------------------

def test_four_hashes_emit_distinct_single_opcodes():
    sha = _unlock_ops("sha256")[0].code
    rip = _unlock_ops("ripemd160")[0].code
    h160 = _unlock_ops("hash160")[0].code
    h256 = _unlock_ops("hash256")[0].code
    assert sha == "OP_SHA256"
    assert rip == "OP_RIPEMD160"
    assert h160 == "OP_HASH160"
    assert h256 == "OP_HASH256"
    assert len({sha, rip, h160, h256}) == 4, (
        "four hash builtins must emit four distinct opcodes"
    )
