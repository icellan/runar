"""The `--ir` entry point must honour the EC size flags, like `--source` does.

`compile_from_ir` used to accept only `disable_constant_folding`, so the three
`ec_*` flags defaulted to False and the CLI's `--ec-*` switches were silently
discarded: the compile succeeded, exited 0, and emitted the unoptimized script.
Measured on one `ecMulGen` IR, Go returned 100,314 hex chars and Python 849,134.

The flags belong on this path. They act in STACK LOWERING, downstream of the
IR, so nothing about consuming pre-lowered ANF makes them inapplicable — unlike
`disable_constant_folding`, which is deliberately forced on for IR input (see
Go's `disableFoldForIRInput`) and is asserted here to stay that way.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PY_DIR = REPO / "compilers" / "python"

SOURCE = """
import { SmartContract, assert, ecMulGen, type Point } from 'runar-lang';

class MulGen extends SmartContract {
  readonly want: Point;
  constructor(want: Point) { super(want); this.want = want; }
  public unlock(k: bigint): void {
    const p: Point = ecMulGen(k);
    assert(p === this.want);
  }
}
"""


def _ir_json(tmp_path: Path) -> Path:
    """Lower the contract to ANF IR with Python's own --source path."""
    src = tmp_path / "MulGen.runar.ts"
    src.write_text(SOURCE)
    out = subprocess.run(
        [sys.executable, "-m", "runar_compiler", "--source", str(src), "--emit-ir"],
        cwd=PY_DIR, capture_output=True, text=True, check=True,
    )
    ir = tmp_path / "mulgen.ir.json"
    ir.write_text(out.stdout)
    json.loads(out.stdout)  # must be valid IR JSON
    return ir


def _hex_len(ir: Path, *flags: str) -> int:
    out = subprocess.run(
        [sys.executable, "-m", "runar_compiler", "--ir", str(ir), "--hex", *flags],
        cwd=PY_DIR, capture_output=True, text=True, check=True,
    )
    return len(out.stdout.strip())


def test_ir_path_honours_ec_flags(tmp_path):
    ir = _ir_json(tmp_path)
    off = _hex_len(ir)
    on = _hex_len(
        ir, "--ec-constant-pool", "--ec-reduction-sinking", "--ec-fixed-base-comb"
    )
    # Not "smaller by something": the flags must do real work on this path.
    assert on < off // 2, f"--ir ignored the EC flags: off={off} on={on}"


def test_ir_path_flags_off_is_unchanged(tmp_path):
    """The default --ir path must not move, or every golden moves with it."""
    ir = _ir_json(tmp_path)
    a = _hex_len(ir)
    b = _hex_len(ir, "--disable-constant-folding")
    # Folding is forced off for IR input either way, so these agree.
    assert a == b
