/**
 * Fold-ON ⇄ fold-OFF ScriptVM equivalence oracle (GAP-101).
 *
 * The checked-in goldens (`expected-ir.json` / `expected-script.hex`) are
 * stamped fold-OFF, and CI enforces cross-tier hex/ANF parity in BOTH fold
 * modes. But cross-tier *agreement* is not a correctness oracle: a constant-fold
 * bug shared identically by all seven tiers would ship undetected — every tier
 * agrees on the same wrong bytes, and no golden covers fold-ON.
 *
 * This test closes that gap. For each fixture with a known accepting/rejecting
 * input, it compiles the SAME source twice — folding OFF and folding ON — runs
 * BOTH compiled locking scripts through the BSV SDK's production Script
 * interpreter (`ScriptExecutionContract`), and asserts they reach the identical
 * accept/reject verdict. Fold-OFF is the golden reference, so any fold pass that
 * changes observable script semantics makes fold-ON diverge here and fails.
 *
 * Coverage is honest and intentionally scoped to the pure-computation and
 * signature fixtures where constant folding actually operates and where an
 * accepting witness can be synthesized from the ABI. Crypto-heavy fixtures
 * (SLH-DSA, WOTS, EC, P-256/384, schnorr, sha256-*) and the 4 Go-only fixtures
 * are not driven here; they need hand-authored witnesses to reach an accepting
 * spend and are covered for cross-tier agreement by the conformance runner.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { PrivateKey } from '@bsv/sdk';
import { ScriptExecutionContract, type ScriptExecResult } from '../script-execution.js';
import { ALICE, BOB, CHARLIE, DAVE } from '../test-keys.js';

const CONFORMANCE = resolve(__dirname, '../../../../conformance/tests');

function readContract(name: string): string {
  const manifest = JSON.parse(
    readFileSync(resolve(CONFORMANCE, name, 'source.json'), 'utf8'),
  ) as { sources: Record<string, string> };
  const tsRel = manifest.sources['.runar.ts'];
  if (!tsRel) throw new Error(`Fixture ${name} has no .runar.ts source mapping`);
  return readFileSync(resolve(CONFORMANCE, name, tsRel), 'utf8');
}

type CtorArgs = Record<string, bigint | boolean | string>;
type MethodArgs = (bigint | boolean | string)[];

interface PureCase {
  kind: 'pure';
  fixture: string;
  ctor: CtorArgs;
  method: string;
  args: MethodArgs;
  expect: boolean;
  label?: string;
}

interface SignedCase {
  kind: 'signed';
  fixture: string;
  ctor: CtorArgs;
  method: string;
  args: MethodArgs;
  sigArgIndex: number;
  privKeyHex: string;
  expect: boolean;
  label?: string;
}

type FoldCase = PureCase | SignedCase;

/**
 * Known accepting/rejecting inputs for fold-relevant fixtures. Reuses the
 * exact inputs proven in `script-execution.test.ts`; extend this table to widen
 * fold coverage as new pure-compute fixtures land.
 */
const CASES: FoldCase[] = [
  // arithmetic: 3+7=10, 3-7=-4, 3*7=21, 3/7=0 → sum 27
  { kind: 'pure', fixture: 'arithmetic', ctor: { target: 27n }, method: 'verify', args: [3n, 7n], expect: true },
  { kind: 'pure', fixture: 'arithmetic', ctor: { target: 0n }, method: 'verify', args: [3n, 7n], expect: false },

  // boolean-logic
  { kind: 'pure', fixture: 'boolean-logic', ctor: { threshold: 2n }, method: 'verify', args: [5n, 3n, false], expect: true },
  { kind: 'pure', fixture: 'boolean-logic', ctor: { threshold: 10n }, method: 'verify', args: [5n, 3n, true], expect: false },

  // if-else
  { kind: 'pure', fixture: 'if-else', ctor: { limit: 10n }, method: 'check', args: [15n, true], expect: true },
  { kind: 'pure', fixture: 'if-else', ctor: { limit: 10n }, method: 'check', args: [5n, false], expect: false },

  // bounded-loop: sum (3+0)+(3+1)+..+(3+4)=25
  { kind: 'pure', fixture: 'bounded-loop', ctor: { expectedSum: 25n }, method: 'verify', args: [3n], expect: true },
  { kind: 'pure', fixture: 'bounded-loop', ctor: { expectedSum: 99n }, method: 'verify', args: [3n], expect: false },

  // basic-p2pkh (signature path)
  { kind: 'signed', fixture: 'basic-p2pkh', ctor: { pubKeyHash: ALICE.pubKeyHash }, method: 'unlock', args: ['placeholder', ALICE.pubKey], sigArgIndex: 0, privKeyHex: ALICE.privKey, expect: true },
  { kind: 'signed', fixture: 'basic-p2pkh', ctor: { pubKeyHash: ALICE.pubKeyHash }, method: 'unlock', args: ['placeholder', BOB.pubKey], sigArgIndex: 0, privKeyHex: BOB.privKey, expect: false },

  // multi-method (signature path): threshold = amount*2+1 = 6*2+1 = 13 > 10
  { kind: 'signed', fixture: 'multi-method', ctor: { owner: CHARLIE.pubKey, backup: DAVE.pubKey }, method: 'spendWithOwner', args: ['placeholder', 6n], sigArgIndex: 0, privKeyHex: CHARLIE.privKey, expect: true },

  // if-without-else: count++ per (arg > threshold); assert(count > 0). Discriminating.
  { kind: 'pure', fixture: 'if-without-else', ctor: { threshold: 5n }, method: 'check', args: [10n, 3n], expect: true },
  { kind: 'pure', fixture: 'if-without-else', ctor: { threshold: 5n }, method: 'check', args: [2n, 3n], expect: false },

  // bitwise-ops: ctor bakes a,b as constants so `a & b` etc. are foldable; guards
  // are tautologies (always accept) — exercises fold on bitwise/shift constants.
  { kind: 'pure', fixture: 'bitwise-ops', ctor: { a: 12n, b: 10n }, method: 'testBitwise', args: [], expect: true },
  { kind: 'pure', fixture: 'bitwise-ops', ctor: { a: 12n, b: 10n }, method: 'testShift', args: [], expect: true },

  // shift-ops: ctor bakes a; `a << k` / `a >> k` foldable; tautology-guarded.
  { kind: 'pure', fixture: 'shift-ops', ctor: { a: 8n }, method: 'testShift', args: [], expect: true },

  // if-without-else-multi-temp: `other(x)` asserts x === x — always accepts.
  { kind: 'pure', fixture: 'if-without-else-multi-temp', ctor: {}, method: 'other', args: ['00'], expect: true },
];

function runFixture(tc: FoldCase, disableConstantFolding: boolean): ScriptExecResult {
  const src = readContract(tc.fixture);
  const fileName = `${tc.fixture}.runar.ts`;
  const c = ScriptExecutionContract.fromSource(src, tc.ctor, fileName, { disableConstantFolding });
  if (tc.kind === 'signed') {
    return c.executeSigned(tc.method, tc.args, tc.sigArgIndex, new PrivateKey(tc.privKeyHex, 16));
  }
  return c.execute(tc.method, tc.args);
}

describe('GAP-101: fold-ON ⇄ fold-OFF ScriptVM equivalence', () => {
  for (const tc of CASES) {
    const desc = `${tc.fixture} [${tc.method}] ${tc.label ?? (tc.expect ? 'accept' : 'reject')}`;
    it(desc, () => {
      const foldOff = runFixture(tc, true);
      const foldOn = runFixture(tc, false);

      // Core oracle: fold-ON must reach the same verdict as fold-OFF (the golden
      // reference). A shared all-tier fold bug that changes semantics fails here.
      expect(foldOn.success).toBe(foldOff.success);

      // Anchor both modes to ground truth so the differential can't pass by both
      // modes being wrong the same way.
      expect(foldOff.success).toBe(tc.expect);
    });
  }

  it('exercises fold-relevant fixtures (coverage guard)', () => {
    // Fail loudly if the table is emptied/regressed, so the oracle can't silently
    // become a no-op.
    expect(CASES.length).toBeGreaterThanOrEqual(17);
    const fixtures = new Set(CASES.map(c => c.fixture));
    expect(fixtures.size).toBeGreaterThanOrEqual(9);
  });
});
