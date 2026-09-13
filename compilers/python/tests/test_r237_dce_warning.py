"""R-237 (CL-GAP-013): the DCE warning for a dropped readonly field never
reached this tier's CLI.

The check exists — `_warn_dropped_readonly_fields`, called from
`_compile_from_source_str_with_result` — but `compile_from_source_collecting_warnings`,
which is what `__main__` calls, returned only the VALIDATOR's warnings. So the
notice was computed and thrown away at the boundary, and an author whose field
vanished from the locking script heard it from ts, go, zig and java but not from
here. Same shape as R-162 in the Go tier.
"""

import tempfile
from pathlib import Path

from runar_compiler.compiler import compile_from_source_collecting_warnings

UNREAD = """
import { SmartContract, assert } from 'runar-lang';

export class UnreadField extends SmartContract {
  readonly unused: bigint;
  readonly limit: bigint;

  constructor(unused: bigint, limit: bigint) {
    super(unused, limit);
    this.unused = unused;
    this.limit = limit;
  }

  public unlock(x: bigint): void {
    assert(x < this.limit);
  }
}
"""

READ = UNREAD.replace("assert(x < this.limit);", "assert(x < this.limit + this.unused);")


def _warnings_for(source: str) -> list[str]:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "UnreadField.runar.ts"
        p.write_text(source)
        _artifact, warnings = compile_from_source_collecting_warnings(str(p))
        return list(warnings)


def test_warns_when_a_readonly_field_is_dropped():
    warnings = _warnings_for(UNREAD)
    assert any("readonly field 'unused'" in w and "eliminated by DCE" in w for w in warnings), (
        f"the dropped-field notice did not reach the caller: {warnings!r}"
    )


def test_does_not_warn_when_the_field_is_read():
    warnings = _warnings_for(READ)
    assert not any("readonly field 'unused'" in w for w in warnings), (
        f"a referenced field must not warn: {warnings!r}"
    )


def test_does_not_warn_for_a_field_that_is_used():
    warnings = _warnings_for(UNREAD)
    assert not any("readonly field 'limit'" in w for w in warnings), (
        f"'limit' is read by unlock and must not warn: {warnings!r}"
    )
