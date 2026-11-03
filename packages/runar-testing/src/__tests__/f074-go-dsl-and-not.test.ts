/**
 * F-074 / CL-BUG-192 — the Go tier's .runar.go parser must not compile Go's
 * bit-clear operator `&^` as an addition.
 *
 * `mapGoOp` (compilers/go/frontend/parser_gocontract.go) had no case for
 * token.AND_NOT and fell through to `return "+"`. `assert((a &^ b) == 4)`
 * compiled to `OP_ADD OP_4 OP_NUMEQUAL` with no diagnostic.
 *
 * The reference is the TS .runar.go parser: it reads `&^` as `&` followed by
 * the prefix complement `^`, i.e. `a & ~b` (`OP_INVERT OP_AND`), which is Go's
 * definition of bit clear. The Rust, Python, Zig, Ruby and Java .runar.go
 * parsers produce the same; only Go diverged.
 *
 * THE ATTACK, run on @bsv/sdk's production `Spend` under the strict v1 rule
 * set (newConsensusSpend): unlock with a = 2, b = 2. The source forbids it
 * (2 &^ 2 = 0, not 4). Before the fix the Go-compiled script computed 2 + 2
 * and ACCEPTED it. After the fix the Go tier emits the reference's bytes and
 * rejects it. The honest spend a = 6, b = 2 (6 &^ 2 = 4) is the control: it is
 * accepted by the reference script and by the fixed Go script, so a rejection
 * of the attack is not a harness artefact.
 *
 * What this proves: for this contract the Go tier's script is byte-identical
 * to the TS reference's, rejects the spend the source forbids and accepts the
 * one it allows.
 * What it does not prove: `&^` in larger expressions, where the Go tier uses Go
 * precedence and the TS parser TypeScript precedence for every bitwise
 * operator (a separate, pre-existing divergence); anything about the other
 * tiers (they were probed out of band — see the F-074 remediation log).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import { compile } from 'runar-compiler';
import { newConsensusSpend, CONSENSUS_SPEND_CONTEXT } from '../consensus-spend.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const GO_BIN = join(REPO, 'compilers', 'go', 'runar-go');
const TMP = mkdtempSync(join(tmpdir(), 'runar-f074-'));

const SOURCE = `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type AndNot struct {
	runar.SmartContract
}

func (c *AndNot) Check(a runar.Bigint, b runar.Bigint) {
	runar.Assert((a &^ b) == 4)
}
`;

/** Minimal push of a small non-negative script number (1..16 → OP_1..OP_16). */
function pushSmall(n: number): string {
  if (n < 1 || n > 16) throw new Error(`pushSmall: ${n} out of range`);
  return (0x50 + n).toString(16);
}

function spend(lockingHex: string, a: number, b: number): boolean {
  const s = newConsensusSpend({
    ...CONSENSUS_SPEND_CONTEXT,
    lockingScript: LockingScript.fromHex(lockingHex),
    unlockingScript: UnlockingScript.fromHex(pushSmall(a) + pushSmall(b)),
    otherInputs: [],
    outputs: [],
  });
  try {
    return s.validate();
  } catch {
    return false;
  }
}

function referenceHex(): string {
  const r = compile(SOURCE, { fileName: 'AndNot.runar.go' });
  if (!r.success || !r.scriptHex) {
    throw new Error(`TS reference refused: ${r.diagnostics.map((d) => d.message).join('; ')}`);
  }
  return r.scriptHex;
}

function goHex(): string {
  if (!existsSync(GO_BIN)) {
    throw new Error(`missing ${GO_BIN} — build it with: cd compilers/go && go build -o runar-go .`);
  }
  const file = join(TMP, 'AndNot.runar.go');
  writeFileSync(file, SOURCE);
  const res = spawnSync(GO_BIN, ['--source', file, '--hex'], { encoding: 'utf-8' });
  if (res.status !== 0) throw new Error(`runar-go failed: ${res.stderr || res.stdout}`);
  return res.stdout.trim();
}

describe('F-074: Go .runar.go `&^` is bit clear, not addition', () => {
  it('the reference script rejects the forbidden spend and accepts the honest one (control)', () => {
    const hex = referenceHex();
    expect(spend(hex, 6, 2)).toBe(true);
    expect(spend(hex, 2, 2)).toBe(false);
  });

  it('the Go tier emits the reference bytes', () => {
    expect(goHex()).toBe(referenceHex());
  });

  it('the Go-compiled script rejects a = 2, b = 2 (2 &^ 2 = 0)', () => {
    expect(spend(goHex(), 2, 2)).toBe(false);
  });

  it('the Go-compiled script accepts a = 6, b = 2 (6 &^ 2 = 4)', () => {
    expect(spend(goHex(), 6, 2)).toBe(true);
  });
});
