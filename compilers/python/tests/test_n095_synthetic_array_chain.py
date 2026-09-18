"""N-095 — the synthetic-array chain on ``ANFProperty`` is wire data.

The expand-fixed-arrays pass desugars a ``FixedArray`` property into scalar
siblings and hangs a chain of ``{base, index, length}`` levels off each leaf.
The artifact assembler regroups those siblings back into a single FixedArray
state/ABI entry by reading that chain off the *ANF program*, not off the AST —
so an ANF that loses the field still compiles to byte-identical script but
degrades the SDK's ``state.grid`` accessor into four raw scalars. The harm is
invisible to every hex-comparing test in the repo, which is why it survived.

Python carried two halves of the same defect:

1. ``--emit-ir`` listed ``synthetic_array_chain`` in ``_IR_EXCLUDED_FIELDS``,
   so it emitted nothing at all; and
2. the loader read only ``__syntheticArrayChain`` — Rust's dialect — so it
   could regroup Rust's ANF but not its own, nor Go's, nor Ruby's.

The settled spelling is Go's ``syntheticArrayChain``.
"""

from __future__ import annotations

import json
from pathlib import Path

from runar_compiler import __main__ as cli_main
from runar_compiler.compiler import compile_from_ir, compile_from_source, compile_source_to_ir

PYTHON_COMPILER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = PYTHON_COMPILER_DIR.parent.parent
ANF_SCHEMA = REPO_ROOT / "packages" / "runar-ir-schema" / "src" / "schemas" / "anf-ir.schema.json"

GRID_SRC = """\
import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class Grid2x2 extends StatefulSmartContract {
  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public set00(v: bigint) {
    this.grid[0][0] = v;
    assert(true);
  }

  public set11(v: bigint) {
    this.grid[1][1] = v;
    assert(true);
  }
}
"""

SCALAR_SRC = """\
import { StatefulSmartContract, assert } from 'runar-lang';

export class Counter extends StatefulSmartContract {
  count: bigint = 0n;

  constructor() {
    super();
  }

  public increment() {
    this.count = this.count + 1n;
    assert(true);
  }
}
"""


def _write(tmp_path: Path, src: str, name: str) -> Path:
    path = tmp_path / name
    path.write_text(src)
    return path


def _emit_ir(tmp_path: Path, src: str, name: str = "Grid2x2.runar.ts") -> dict:
    """The ANF JSON this tier emits, round-tripped through json so the test
    only ever sees wire types."""
    program = compile_source_to_ir(str(_write(tmp_path, src, name)))
    return json.loads(json.dumps(cli_main._anf_to_camel_dict(program)))


def _schema_property_keys() -> list[str]:
    schema = json.loads(ANF_SCHEMA.read_text())
    defn = schema["$defs"]["ANFProperty"]
    assert defn["additionalProperties"] is False, (
        "$defs.ANFProperty is no longer additionalProperties:false — this test's "
        "premise (an undeclared key is a schema violation) no longer holds"
    )
    return list(defn["properties"])


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------


def test_every_emitted_property_key_is_declared_in_the_schema(tmp_path: Path) -> None:
    allowed = _schema_property_keys()
    for i, prop in enumerate(_emit_ir(tmp_path, GRID_SRC)["properties"]):
        for key in prop:
            assert key in allowed, (
                f"leaf {i}: emitted ANFProperty key {key!r} is not declared in "
                "$defs.ANFProperty (additionalProperties:false)"
            )


def test_expanded_leaves_carry_the_camel_case_chain(tmp_path: Path) -> None:
    props = _emit_ir(tmp_path, GRID_SRC)["properties"]
    assert len(props) == 4, "expected 4 expanded leaves"

    want = [(0, 0), (0, 1), (1, 0), (1, 1)]
    for i, prop in enumerate(props):
        assert "synthetic_array_chain" not in prop, f"leaf {i} emits the snake spelling"
        assert "__syntheticArrayChain" not in prop, f"leaf {i} emits the TS AST-marker spelling"
        chain = prop.get("syntheticArrayChain")
        assert chain is not None, f"leaf {i} has no syntheticArrayChain key (keys: {list(prop)})"
        assert len(chain) == 2, f"leaf {i}: a 2x2 grid nests twice"
        assert chain[0]["base"] == "grid"
        assert chain[0]["index"] == want[i][0]
        assert chain[0]["length"] == 2
        assert chain[1]["index"] == want[i][1]
        assert chain[1]["length"] == 2


def test_scalar_property_carries_no_chain(tmp_path: Path) -> None:
    """Byte-neutrality control. An empty chain must be OMITTED, not emitted as
    ``[]``: every other tier skips it (Go ``omitempty``, Rust
    ``skip_serializing_if``), and an extra key on every property of every
    FixedArray-free contract would move the ANF bytes of the whole suite."""
    for prop in _emit_ir(tmp_path, SCALAR_SRC, "Counter.runar.ts")["properties"]:
        for key in prop:
            assert "ynthetic" not in key, (
                f"a FixedArray-free contract grew a synthetic-array key: {key}"
            )


# ---------------------------------------------------------------------------
# The harm: the ABI, not the hex
# ---------------------------------------------------------------------------


def test_self_ir_round_trip_still_regroups(tmp_path: Path) -> None:
    path = _write(tmp_path, GRID_SRC, "Grid2x2.runar.ts")

    from_source = compile_from_source(str(path))
    assert [f.name for f in from_source.state_fields] == ["grid"], (
        "source mode no longer regroups the expanded leaves"
    )

    ir_path = tmp_path / "ir.json"
    program = compile_source_to_ir(str(path))
    ir_path.write_text(json.dumps(cli_main._anf_to_camel_dict(program)))

    from_ir = compile_from_ir(str(ir_path))
    assert [f.name for f in from_ir.state_fields] == ["grid"], (
        "Python could not read back an ANF it had just written: the FixedArray "
        "regrouping was lost, so the SDK sees four raw scalars instead of state.grid"
    )
    fa = from_ir.state_fields[0].fixed_array
    assert fa is not None, "regrouped state field carries no fixedArray metadata"
    assert fa["syntheticNames"] == [
        "grid__0__0",
        "grid__0__1",
        "grid__1__0",
        "grid__1__1",
    ]

    assert from_source.script == from_ir.script, (
        "the chain must be ABI-only: it must not move a single script byte"
    )


def test_foreign_anf_with_the_settled_spelling_regroups(tmp_path: Path) -> None:
    """The loader must key off the settled spelling, not Rust's old dialect."""
    program = compile_source_to_ir(str(_write(tmp_path, GRID_SRC, "Grid2x2.runar.ts")))
    doc = json.loads(json.dumps(cli_main._anf_to_camel_dict(program)))

    ir_path = tmp_path / "foreign.json"
    ir_path.write_text(json.dumps(doc))
    artifact = compile_from_ir(str(ir_path))
    assert [f.name for f in artifact.state_fields] == ["grid"]

    # And the AST-marker spelling must NOT be honoured any more: a document
    # carrying only `__syntheticArrayChain` is, by the schema, a document with
    # an undeclared key and no chain.
    for prop in doc["properties"]:
        prop["__syntheticArrayChain"] = prop.pop("syntheticArrayChain")
    stale = tmp_path / "stale.json"
    stale.write_text(json.dumps(doc))
    assert [f.name for f in compile_from_ir(str(stale)).state_fields] != ["grid"]
