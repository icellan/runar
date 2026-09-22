"""F-013 (CL-BUG-214): an index assignment whose root is NOT a FixedArray
property must be rejected, not silently discarded.

``expand_fixed_arrays`` rewrites ``this.arr[i] = v`` only when ``arr`` is a
FixedArray property. Any other index target (``this.blob[0n] = 7n`` on a
``ByteString`` property, ``b[0n] = 7n`` on a local, a parameter) survives to
``anf_lower._lower_assignment``, whose fallback lowers the target as a READ and
drops the value: no ``update_prop``, no diagnostic, and a deployable script
whose state never changes. Neither the validator nor the type checker (which
types such an index as ``<unknown>``, the lattice top) rejected the shape.

What this proves: the validator rejects every non-FixedArray index-assignment
shape below with a located diagnostic, so ``compile_from_source`` fails closed;
FixedArray index writes (flat, runtime index, nested) still validate clean.

What this does NOT prove: anything about other tiers (TS/Go/Rust/Zig at the
time of writing also accept the shape — tracked separately), nor any semantics
for byte-level writes into a ByteString, which Rúnar does not define.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import ValidationResult, validate

NEEDLE = "index assignment"


def _validate(source: str, file_name: str = "Test.runar.ts") -> ValidationResult:
    result = parse_source(source, file_name)
    assert result.contract is not None, f"parse failed: {result.errors}"
    return validate(result.contract)


BYTESTRING_PROP = """
class Blob extends StatefulSmartContract {
  blob: ByteString;

  constructor(blob: ByteString) {
    super(blob);
    this.blob = blob;
  }

  public poke() {
    this.blob[0n] = 7n;
    assert(true);
  }
}
"""

BYTESTRING_PROP_COMPOUND = """
class Blob extends StatefulSmartContract {
  blob: ByteString;

  constructor(blob: ByteString) {
    super(blob);
    this.blob = blob;
  }

  public poke() {
    this.blob[0n] += 7n;
    assert(true);
  }
}
"""

LOCAL_TARGET = """
class Loc extends SmartContract {
  readonly h: ByteString;

  constructor(h: ByteString) {
    super(h);
    this.h = h;
  }

  public unlock(b: ByteString) {
    let c: ByteString = b;
    c[0n] = 7n;
    assert(c == this.h);
  }
}
"""

PARAM_TARGET = """
class Par extends SmartContract {
  readonly h: ByteString;

  constructor(h: ByteString) {
    super(h);
    this.h = h;
  }

  public unlock(b: ByteString) {
    b[0n] = 7n;
    assert(b == this.h);
  }
}
"""


@pytest.mark.parametrize(
    "source",
    [BYTESTRING_PROP, BYTESTRING_PROP_COMPOUND, LOCAL_TARGET, PARAM_TARGET],
    ids=["bytestring-prop", "bytestring-prop-compound", "local", "param"],
)
def test_non_fixed_array_index_assignment_is_rejected(source: str) -> None:
    result = _validate(source)
    hits = [d for d in result.errors if NEEDLE in d.message]
    assert hits, f"expected an '{NEEDLE}' error, got: {result.error_strings()}"
    loc = hits[0].loc
    assert loc is not None and loc.line > 0, f"diagnostic carries no location: {hits[0]}"


def test_bytestring_prop_index_assignment_does_not_compile() -> None:
    # End-to-end: before the fix this compiled to an 885-byte script with no
    # update_prop for `blob` — the write was silently dropped.
    result = compile_from_source_str_with_result(BYTESTRING_PROP, "Blob.runar.ts")
    assert not result.success, "compiled a script that silently drops the write"
    assert any(NEEDLE in d.message for d in result.diagnostics), result.diagnostics


FIXED_ARRAY_WRITES = """
class Board extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public set(i: bigint, v: bigint) {
    this.board[i] = v;
    this.board[0n] = v;
    this.grid[1n][i] = v;
  }
}
"""


def test_fixed_array_index_assignment_still_validates() -> None:
    result = _validate(FIXED_ARRAY_WRITES)
    assert not [d for d in result.errors if NEEDLE in d.message], result.error_strings()
