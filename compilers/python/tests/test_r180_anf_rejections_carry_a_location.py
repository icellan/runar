"""R-180 (CL-BUG-175): ANF-stage rejections reach the user without a location.

The finding has two halves.

HALF ONE — a raw traceback escaping `--emit-ir` / `--emit-ir-to` — is already
CLOSED. Both branches in `__main__.py` now carry a catch-all that reports
`Compilation error: ...` and exits 1, the same shape the `--source` path uses.
The first case below is the regression guard for that, not a new claim.

HALF TWO is open and is what the rest of this file is about. The bare
`ValueError`s raised during ANF lowering are ordinary input rejections — the
user wrote something the language does not accept — but unlike every
validation-stage rejection they arrive with no `file:line:column`. Compare, for
the same contract shape:

    validation   LoopBound.runar.ts:8:4: for loop bound must be a compile-time constant
    ANF lowering For loop counting up (i++) must use '<' or '<=' (got '>').

Four of the nine are reachable from ordinary source, verified by compiling each
shape below through the real CLI; the other five sit behind checks the validator
already makes, so the validator's located message is what the user sees.

CROSS-TIER NOTE, recorded rather than acted on here: the peers are no better.
Go emits these same rejections through a recovered panic, so its user-facing
text reads `anf lowering panic: For loop counting up ...` — location-less AND
leaking the word "panic" for an ordinary rejection. Message text is not gated
across tiers (`conformance/negatives/rejection-parity.test.ts` compares
accept/reject verdicts, not wording), so improving Python's does not break
parity. The peers are a separate piece of work.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[1]

# `<path>:<line>:<col>: ` — the prefix every validation-stage rejection carries.
LOCATED = re.compile(r"[^\s:]+\.runar\.ts:\d+:\d+: ")

BIG_STATE = """import { StatefulSmartContract, assert } from 'runar-lang';

export class BigState extends StatefulSmartContract {
  count: bigint = 99999999999999999999999999n;

  constructor() {
    super();
  }

  public bump() {
    this.count = this.count + 1n;
    assert(true);
  }
}
"""

LOOP_COUNT = """import { SmartContract, assert } from 'runar-lang';

export class LoopCount extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public unlock(x: bigint) {
    let acc: bigint = 0n;
    for (let i = 0n; i < 10001n; i++) {
      acc = acc + x;
    }
    assert(acc >= 0n);
  }
}
"""

LOOP_OP = """import { SmartContract, assert } from 'runar-lang';

export class LoopOp extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public unlock(x: bigint) {
    let acc: bigint = 0n;
    for (let i = 0n; i > 5n; i++) {
      acc = acc + x;
    }
    assert(acc >= 0n);
  }
}
"""

COND_OUT = """import { StatefulSmartContract, assert } from 'runar-lang';

export class CondOut extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public go(v: bigint) {
    let na: bigint = 0n;
    let nb: bigint = 0n;
    if (v > 1n) {
      na = v;
      nb = v + 1n;
      this.addOutput(1000n, this.count);
    }
    this.count = na + nb;
    assert(true);
  }
}
"""

# A shape the VALIDATOR rejects, so the located format is pinned by a case that
# already passes — the test states the target rather than inventing it.
LOOP_BOUND = """import { SmartContract, assert } from 'runar-lang';

export class LoopBound extends SmartContract {
  readonly n: bigint;

  constructor(n: bigint) {
    super(n);
    this.n = n;
  }

  public unlock(x: bigint) {
    let acc: bigint = 0n;
    for (let i = 0n; i < this.n; i++) {
      acc = acc + x;
    }
    assert(acc >= 0n);
  }
}
"""

REACHABLE = [
    ("BigState", BIG_STATE, "does not fit the fixed 8-byte sign-magnitude state word"),
    ("LoopCount", LOOP_COUNT, "exceeding the maximum loop count"),
    ("LoopOp", LOOP_OP, "must use '<' or '<='"),
    ("CondOut", COND_OUT, "both declares outputs"),
]


def _compile(tmp_path: Path, name: str, source: str, *extra: str) -> subprocess.CompletedProcess:
    src = tmp_path / f"{name}.runar.ts"
    src.write_text(source)
    return subprocess.run(
        [sys.executable, "-m", "runar_compiler", "--source", str(src), *extra],
        cwd=str(PKG_ROOT),
        capture_output=True,
        text=True,
    )


def test_a_validation_rejection_is_located(tmp_path):
    """The format the ANF-stage rejections must match. Passes today."""
    res = _compile(tmp_path, "LoopBound", LOOP_BOUND, "--hex")
    assert "for loop bound must be a compile-time constant" in res.stderr, res.stderr
    assert LOCATED.search(res.stderr), (
        "the validator stopped emitting file:line:column; this test's target is gone:\n"
        + res.stderr
    )


def test_emit_ir_reports_a_rejection_rather_than_a_traceback(tmp_path):
    """Half one of the finding, already closed — kept as the regression guard."""
    for name, source, _ in REACHABLE:
        res = _compile(tmp_path, name, source, "--emit-ir")
        assert res.returncode != 0, f"{name}: --emit-ir accepted a program it must reject"
        assert "Traceback" not in res.stderr, (
            f"{name}: --emit-ir dumped a Python traceback:\n" + res.stderr[-1500:]
        )


def test_every_reachable_anf_rejection_is_located(tmp_path):
    """Half two: each of these must name where in the source the problem is."""
    unlocated: list[str] = []
    for name, source, needle in REACHABLE:
        res = _compile(tmp_path, name, source, "--hex")
        assert res.returncode != 0, f"{name}: compiled a program it must reject"
        assert needle in res.stderr, (
            f"{name}: rejected for a different reason than this case is built for:\n"
            + res.stderr
        )
        if not LOCATED.search(res.stderr):
            unlocated.append(f"{name}: {res.stderr.strip().splitlines()[0][:120]}")
    assert unlocated == [], (
        "these ANF-stage rejections arrived with no file:line:column, while every "
        "validation-stage rejection carries one:\n  " + "\n  ".join(unlocated)
    )
