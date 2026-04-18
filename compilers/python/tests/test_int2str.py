"""Tests for the ``int2str`` built-in.

Verifies the Python Rúnar compiler implements ``int2str(n, byteLen)`` as
an alias for ``num2bin`` (lowering to ``OP_NUM2BIN``), matching the
TypeScript, Go, Rust, Zig, and Ruby compilers.

The Python source uses ``int_to_str`` (snake_case); the parser must rewrite
it to the canonical ``int2str`` AST name. The Python runtime also exposes
``int_to_str`` for native-Python contract testing.
"""

from __future__ import annotations

from runar_compiler.compiler import compile_from_source_str_with_result


PY_SOURCE = """
from runar import SmartContract, Bigint, ByteString, public, assert_, int_to_str, len_

class Encoder(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def unlock(self):
        out: ByteString = int_to_str(self.n, 4)
        assert_(len_(out) == 4)
"""


TS_SOURCE = """
import { SmartContract, assert } from 'runar-lang';
import type { ByteString } from 'runar-lang';

export class Encoder extends SmartContract {
  constructor(readonly n: bigint) { super(n); }
  public unlock(): void {
    const out: ByteString = int2str(this.n, 4n);
    assert(len(out) === 4n);
  }
}
"""


def _compile(source: str, file_name: str) -> str:
    result = compile_from_source_str_with_result(
        source,
        file_name,
        disable_constant_folding=True,
    )
    assert result.success, (
        f"compilation of {file_name} failed: "
        + "; ".join(
            d.message if hasattr(d, "message") else str(d)
            for d in result.diagnostics
        )
    )
    assert result.script_hex is not None
    return result.script_hex


class TestInt2Str:
    def test_python_int_to_str_compiles(self) -> None:
        """Python ``int_to_str`` (snake_case) must compile without errors."""
        hex_out = _compile(PY_SOURCE, "Encoder.runar.py")
        assert "54" in hex_out  # push of 4 (OP_4 = 0x54) for the byteLen arg
        assert "80" in hex_out  # OP_NUM2BIN = 0x80

    def test_python_matches_typescript(self) -> None:
        """Python ``int_to_str`` lowers to identical script bytes as TS ``int2str``."""
        py_hex = _compile(PY_SOURCE, "Encoder.runar.py")
        ts_hex = _compile(TS_SOURCE, "Encoder.runar.ts")
        assert py_hex == ts_hex, (
            f"Python/TypeScript int2str parity mismatch:\n"
            f"  python:     {py_hex}\n"
            f"  typescript: {ts_hex}"
        )

    def test_emits_op_num2bin(self) -> None:
        """``int2str`` must emit the ``OP_NUM2BIN`` opcode."""
        result = compile_from_source_str_with_result(
            PY_SOURCE,
            "Encoder.runar.py",
            disable_constant_folding=True,
        )
        assert result.success, "\n".join(
            d.message if hasattr(d, "message") else str(d)
            for d in result.diagnostics
        )
        assert "OP_NUM2BIN" in (result.script_asm or "")


