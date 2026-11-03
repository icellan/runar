"""N-002 (CL-BUG-214, the cross-tier half of F-013): the shapes the other six
tiers now refuse, pinned for this tier too.

F-013 added the rule here (validator.py) and tested the ByteString-property,
``+=``, local and parameter shapes (test_f013_index_assign_non_fixed_array.py).
N-002 ported it verbatim to TS, Go, Rust, Zig, Ruby and Java and widened the
shape set; this file pins the widened set in the tier that already had the
rule, so all seven tiers are held to the same list.

What this proves: this tier refuses, with the shared diagnostic and a
location, a runtime-index, nested-index, member-chained and every supported
compound-op write to a ByteString property, plus the Python-surface
ByteString-property / local / parameter writes; FixedArray compound and ``++``
writes still validate.
What this does NOT prove: anything about the other tiers (their own suites and
conformance/negatives/N81-N94 cover that). These cases passed at HEAD -- they
lock parity, they did not reproduce a defect in this tier.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate

NEEDLE = (
    "index assignment is only supported on FixedArray contract properties; "
    "the target here is not a FixedArray property"
)


def _blob(body: str) -> str:
    return f"""
class Blob extends StatefulSmartContract {{
  blob: ByteString;

  constructor(blob: ByteString) {{
    super(blob);
    this.blob = blob;
  }}

  public poke(i: bigint) {{
    {body}
    assert(true);
  }}
}}
"""


PY_PROP = """from runar import StatefulSmartContract, ByteString, public, assert_


class Blob(StatefulSmartContract):
    blob: ByteString

    def __init__(self, blob: ByteString):
        super().__init__(blob)
        self.blob = blob

    @public
    def poke(self):
        self.blob[0] = 7
        assert_(True)
"""

PY_LOCAL_PARAM = """from runar import SmartContract, ByteString, public, assert_


class Loc(SmartContract):
    h: ByteString

    def __init__(self, h: ByteString):
        super().__init__(h)
        self.h = h

    @public
    def unlock(self, b: ByteString):
        c = b
        c[0] = 7
        b[1] = 7
        assert_(c == self.h)
"""


def _needle_hits(source: str, file_name: str) -> int:
    parsed = parse_source(source, file_name)
    assert parsed.contract is not None, f"parse failed: {parsed.errors}"
    hits = [d for d in validate(parsed.contract).errors if d.message == NEEDLE]
    for d in hits:
        assert d.loc is not None and d.loc.line > 0, f"diagnostic carries no location: {d}"
    return len(hits)


@pytest.mark.parametrize(
    "body",
    [
        "this.blob[i] = 7n;",
        "this.blob[0n] -= 7n;",
        "this.blob[0n] *= 7n;",
        "this.blob[0n] /= 7n;",
        "this.blob[0n] %= 7n;",
        "this.blob[0n][1n] = 7n;",
        "this.blob.x[0n] = 7n;",
    ],
)
def test_widened_ts_shapes_are_refused(body: str) -> None:
    src = _blob(body)
    assert _needle_hits(src, "Blob.runar.ts") == 1
    assert not compile_from_source_str_with_result(src, "Blob.runar.ts").success


@pytest.mark.parametrize(
    "source,file_name,want",
    [(PY_PROP, "Blob.runar.py", 1), (PY_LOCAL_PARAM, "Loc.runar.py", 2)],
    ids=["py-prop", "py-local+param"],
)
def test_python_surface_is_refused(source: str, file_name: str, want: int) -> None:
    assert _needle_hits(source, file_name) == want
    assert not compile_from_source_str_with_result(source, file_name).success


def test_fixed_array_compound_and_increment_still_validate() -> None:
    src = """
class Board extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];

  constructor() {
    super();
  }

  public set(v: bigint) {
    this.board[1n] += v;
    this.board[2n]++;
    assert(true);
  }
}
"""
    assert _needle_hits(src, "Board.runar.ts") == 0
    assert compile_from_source_str_with_result(src, "Board.runar.ts").success
