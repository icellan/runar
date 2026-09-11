"""CL-BUG-104: the Python CLI must not swallow validator warnings.

``ValidationResult`` has carried ``warnings`` / ``warning_strings()`` since
the validator was written, but ``runar_compiler.__main__`` never printed
them, so the SP1 FRI unsoundness disclosure, the ``@embedAlways`` DCE
notices and the sighash advisories were invisible to anyone driving the
compiler from the command line.

Reference behaviour is the Rust (``compilers/rust/src/main.rs``:
``eprintln!("warning: {}", w)``) and Zig (``compilers/zig/src/main.zig``:
``printDiagnostics``) tiers: warnings go to **stderr**, one per line,
prefixed ``warning: ``, and they change neither the exit code nor the bytes
on stdout.

The warning driven here is a real one — V26, "StatefulSmartContract has no
mutable properties", emitted by
``runar_compiler/frontend/validator.py``. No synthetic diagnostic is
injected anywhere.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

PYTHON_COMPILER_DIR = Path(__file__).resolve().parent.parent

WARNING_SOURCE = """import { StatefulSmartContract, assert } from 'runar-lang';

export class WarnStateful extends StatefulSmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(x: bigint): void {
    assert(x < this.limit);
  }
}
"""

CLEAN_SOURCE = """import { SmartContract, assert } from 'runar-lang';

export class CleanStateless extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(x: bigint): void {
    assert(x < this.limit);
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


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body)
    return p


def test_validator_warning_reaches_stderr(tmp_path: Path) -> None:
    src = _write(tmp_path, "WarnStateful.runar.ts", WARNING_SOURCE)
    proc = _run(["--source", str(src), "--hex"])

    assert proc.returncode == 0, f"compile must succeed: {proc.stderr}"
    assert "StatefulSmartContract has no mutable properties" in proc.stderr, (
        f"validator warning did not reach stderr; stderr={proc.stderr!r}"
    )
    assert "warning: " in proc.stderr, (
        f"warning line must carry the 'warning: ' prefix used by Rust/Zig; "
        f"stderr={proc.stderr!r}"
    )
    # stdout is the artifact channel and must stay clean.
    assert proc.stdout.strip(), "stdout must still carry the script hex"
    assert "warning" not in proc.stdout, f"warning leaked into stdout: {proc.stdout!r}"


def test_clean_compile_prints_no_warning_and_exits_zero(tmp_path: Path) -> None:
    src = _write(tmp_path, "CleanStateless.runar.ts", CLEAN_SOURCE)
    proc = _run(["--source", str(src), "--hex"])

    assert proc.returncode == 0, f"clean compile must exit 0: {proc.stderr}"
    assert "warning" not in proc.stderr, (
        f"clean compile must print no warning line; stderr={proc.stderr!r}"
    )
    assert proc.stdout.strip(), "clean compile produced no hex"


def test_parse_only_also_prints_warnings(tmp_path: Path) -> None:
    """``--parse-only`` runs the validator, so it has warnings to report.

    This is the path where the Rust tier prints its warnings
    (``compilers/rust/src/main.rs:148-150``) and where the Zig tier's
    ``printDiagnostics`` also runs. Dropping them here would leave the two
    CLI paths disagreeing about whether the compiler talks.
    """
    src = _write(tmp_path, "WarnStateful.runar.ts", WARNING_SOURCE)
    proc = _run(["--parse-only", "--source", str(src)])

    assert proc.returncode == 0, f"--parse-only must exit 0: {proc.stderr}"
    assert proc.stdout.strip() == "parser ok", (
        f"--parse-only stdout must stay exactly 'parser ok', got {proc.stdout!r}"
    )
    assert "warning: " in proc.stderr, f"--parse-only dropped the warning: {proc.stderr!r}"
    assert "StatefulSmartContract has no mutable properties" in proc.stderr
