/**
 * Script execution tests — verify compiled Bitcoin Script runs correctly
 * in the BSV SDK's production-grade interpreter.
 *
 * These tests compile Rúnar contracts with baked constructor args, build
 * unlocking scripts, and execute them through `@bsv/sdk`'s Spend class.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { PrivateKey } from '@bsv/sdk';
import { ScriptExecutionContract } from '../script-execution.js';
import { TestContract } from '../test-contract.js';
import { ALICE, BOB, CHARLIE, DAVE, EVE, FRANK, GRACE, HEIDI } from '../test-keys.js';

function privKey(hex: string): PrivateKey {
  return new PrivateKey(hex, 16);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CONFORMANCE = resolve(__dirname, '../../../../conformance/tests');

function readContract(name: string): string {
  // Resolve the .runar.ts source via the fixture's source.json (the actual
  // contract lives under examples/ts/<name>/<Name>.runar.ts, not directly
  // inside the conformance dir).
  const manifestPath = resolve(CONFORMANCE, name, 'source.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
    sources: Record<string, string>;
  };
  const tsRel = manifest.sources['.runar.ts'];
  if (!tsRel) throw new Error(`No .runar.ts source for fixture ${name}`);
  return readFileSync(resolve(CONFORMANCE, name, tsRel), 'utf8');
}

// ---------------------------------------------------------------------------
// Pure computation contracts (no checkSig)
// ---------------------------------------------------------------------------

describe('Script execution: pure computation', () => {
  describe('Arithmetic', () => {
    const src = readContract('arithmetic');

    it('succeeds with correct target (3+7=10, 3-7=-4, 3*7=21, 3/7=0 → 27)', () => {
      const c = ScriptExecutionContract.fromSource(src, { target: 27n }, 'arithmetic.runar.ts');
      expect(c.execute('verify', [3n, 7n]).success).toBe(true);
    });

    it('fails with wrong target', () => {
      const c = ScriptExecutionContract.fromSource(src, { target: 0n }, 'arithmetic.runar.ts');
      expect(c.execute('verify', [3n, 7n]).success).toBe(false);
    });

    it('fails with wrong args', () => {
      const c = ScriptExecutionContract.fromSource(src, { target: 27n }, 'arithmetic.runar.ts');
      // 1+1=2, 1-1=0, 1*1=1, 1/1=1 → 4 ≠ 27
      expect(c.execute('verify', [1n, 1n]).success).toBe(false);
    });
  });

  describe('BooleanLogic', () => {
    const src = readContract('boolean-logic');

    it('succeeds when both above threshold', () => {
      // a=5>2, b=3>2, bothAbove=true → assert(true || ...) passes
      const c = ScriptExecutionContract.fromSource(src, { threshold: 2n }, 'boolean-logic.runar.ts');
      expect(c.execute('verify', [5n, 3n, false]).success).toBe(true);
    });

    it('succeeds when one above and flag is false', () => {
      // a=5>2, b=1 not >2, eitherAbove=true, notFlag=!false=true
      // assert(false || (true && true)) → true
      const c = ScriptExecutionContract.fromSource(src, { threshold: 2n }, 'boolean-logic.runar.ts');
      expect(c.execute('verify', [5n, 1n, false]).success).toBe(true);
    });

    it('fails when neither above threshold', () => {
      const c = ScriptExecutionContract.fromSource(src, { threshold: 10n }, 'boolean-logic.runar.ts');
      expect(c.execute('verify', [5n, 3n, true]).success).toBe(false);
    });
  });

  describe('IfElse', () => {
    const src = readContract('if-else');

    it('takes the true branch (value + limit > 0)', () => {
      const c = ScriptExecutionContract.fromSource(src, { limit: 10n }, 'if-else.runar.ts');
      // mode=true → result = 15+10 = 25 > 0
      expect(c.execute('check', [15n, true]).success).toBe(true);
    });

    it('takes the false branch (value - limit > 0)', () => {
      const c = ScriptExecutionContract.fromSource(src, { limit: 10n }, 'if-else.runar.ts');
      // mode=false → result = 15-10 = 5 > 0
      expect(c.execute('check', [15n, false]).success).toBe(true);
    });

    it('fails when result is not positive', () => {
      const c = ScriptExecutionContract.fromSource(src, { limit: 10n }, 'if-else.runar.ts');
      // mode=false → result = 5-10 = -5, not > 0
      expect(c.execute('check', [5n, false]).success).toBe(false);
    });
  });

  describe('BoundedLoop', () => {
    const src = readContract('bounded-loop');

    it('succeeds with correct expected sum', () => {
      // sum = (3+0)+(3+1)+(3+2)+(3+3)+(3+4) = 3+4+5+6+7 = 25
      const c = ScriptExecutionContract.fromSource(src, { expectedSum: 25n }, 'bounded-loop.runar.ts');
      expect(c.execute('verify', [3n]).success).toBe(true);
    });

    it('fails with wrong expected sum', () => {
      const c = ScriptExecutionContract.fromSource(src, { expectedSum: 99n }, 'bounded-loop.runar.ts');
      expect(c.execute('verify', [3n]).success).toBe(false);
    });

    it('succeeds with start=0 (sum = 0+1+2+3+4 = 10)', () => {
      const c = ScriptExecutionContract.fromSource(src, { expectedSum: 10n }, 'bounded-loop.runar.ts');
      expect(c.execute('verify', [0n]).success).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Signature contracts (real keys via BSV SDK)
// ---------------------------------------------------------------------------

describe('Script execution: signatures', () => {
  describe('P2PKH', () => {
    const src = readContract('basic-p2pkh');

    it('succeeds with correct key', () => {
      const pk = privKey(ALICE.privKey);

      const c = ScriptExecutionContract.fromSource(
        src, { pubKeyHash: ALICE.pubKeyHash }, 'basic-p2pkh.runar.ts',
      );
      const result = c.executeSigned('unlock', ['placeholder', ALICE.pubKey], 0, pk);
      expect(result.success).toBe(true);
    });

    it('fails with wrong key (hash mismatch)', () => {
      const wrongPk = privKey(BOB.privKey);

      const c = ScriptExecutionContract.fromSource(
        src, { pubKeyHash: ALICE.pubKeyHash }, 'basic-p2pkh.runar.ts',
      );
      const result = c.executeSigned('unlock', ['placeholder', BOB.pubKey], 0, wrongPk);
      expect(result.success).toBe(false);
    });
  });

  describe('MultiMethod', () => {
    const src = readContract('multi-method');

    it('spendWithOwner succeeds with correct key and amount > 5', () => {
      const ownerPk = privKey(CHARLIE.privKey);

      const c = ScriptExecutionContract.fromSource(
        src, { owner: CHARLIE.pubKey, backup: DAVE.pubKey }, 'multi-method.runar.ts',
      );
      // threshold = amount * 2 + 1 = 6*2+1 = 13 > 10
      const result = c.executeSigned('spendWithOwner', ['placeholder', 6n], 0, ownerPk);
      expect(result.success).toBe(true);
    });

    it('spendWithOwner fails when threshold ≤ 10', () => {
      const ownerPk = privKey(EVE.privKey);

      const c = ScriptExecutionContract.fromSource(
        src, { owner: EVE.pubKey, backup: FRANK.pubKey }, 'multi-method.runar.ts',
      );
      // threshold = 3*2+1 = 7, not > 10
      const result = c.executeSigned('spendWithOwner', ['placeholder', 3n], 0, ownerPk);
      expect(result.success).toBe(false);
    });

    it('spendWithBackup succeeds with correct key', () => {
      const backupPk = privKey(HEIDI.privKey);

      const c = ScriptExecutionContract.fromSource(
        src, { owner: GRACE.pubKey, backup: HEIDI.pubKey }, 'multi-method.runar.ts',
      );
      const result = c.executeSigned('spendWithBackup', ['placeholder'], 0, backupPk);
      expect(result.success).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Dual-oracle: interpreter vs compiled script agree
// ---------------------------------------------------------------------------

describe('Script execution: interpreter vs compiled agreement', () => {
  const contracts: Array<{ name: string; args: Record<string, bigint | boolean>; method: string; params: Record<string, bigint | boolean>; paramArr: (bigint | boolean)[] }> = [
    { name: 'arithmetic', args: { target: 27n }, method: 'verify', params: { a: 3n, b: 7n }, paramArr: [3n, 7n] },
    { name: 'boolean-logic', args: { threshold: 2n }, method: 'verify', params: { a: 5n, b: 3n, flag: false }, paramArr: [5n, 3n, false] },
    { name: 'if-else', args: { limit: 10n }, method: 'check', params: { value: 15n, mode: true }, paramArr: [15n, true] },
    { name: 'bounded-loop', args: { expectedSum: 25n }, method: 'verify', params: { start: 3n }, paramArr: [3n] },
  ];

  for (const tc of contracts) {
    it(`${tc.name}: interpreter and compiled script agree (success)`, () => {
      const src = readContract(tc.name);

      // Interpreter path
      const interp = TestContract.fromSource(src, tc.args, `${tc.name}.runar.ts`);
      const interpResult = interp.call(tc.method, tc.params);

      // Compiled script path
      const compiled = ScriptExecutionContract.fromSource(src, tc.args, `${tc.name}.runar.ts`);
      const scriptResult = compiled.execute(tc.method, tc.paramArr);

      expect(interpResult.success).toBe(true);
      expect(scriptResult.success).toBe(true);
    });
  }

  // Failure cases — both should fail
  const failCases: Array<{ name: string; args: Record<string, bigint | boolean>; method: string; params: Record<string, bigint | boolean>; paramArr: (bigint | boolean)[] }> = [
    { name: 'arithmetic', args: { target: 0n }, method: 'verify', params: { a: 3n, b: 7n }, paramArr: [3n, 7n] },
    { name: 'if-else', args: { limit: 10n }, method: 'check', params: { value: 5n, mode: false }, paramArr: [5n, false] },
    { name: 'bounded-loop', args: { expectedSum: 99n }, method: 'verify', params: { start: 3n }, paramArr: [3n] },
  ];

  for (const tc of failCases) {
    it(`${tc.name}: interpreter and compiled script agree (failure)`, () => {
      const src = readContract(tc.name);

      const interp = TestContract.fromSource(src, tc.args, `${tc.name}.runar.ts`);
      const interpResult = interp.call(tc.method, tc.params);

      const compiled = ScriptExecutionContract.fromSource(src, tc.args, `${tc.name}.runar.ts`);
      const scriptResult = compiled.execute(tc.method, tc.paramArr);

      expect(interpResult.success).toBe(false);
      expect(scriptResult.success).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// Issue #34 regression: hand-unrolled `if` + multi `let` reassignment
//   https://github.com/icellan/runar/issues/34
// Compiled bytecode previously diverged from the interpreter when an outer
// `if` body contained both a nested `if (cond) { local = expr; }` AND a
// subsequent `let p = ...` reassignment. The post-ENDIF stale-copy cleanup
// only handled ONE reassigned local (`break;` after first match), so the
// second reassignment left a stale stack item that shifted depths for the
// next `OP_PICK` in the next outer-if's bound check.
// ---------------------------------------------------------------------------

describe('Script execution: issue #34 — nested-if multi-reassign parity', () => {
  const src = readFileSync(
    resolve(__dirname, '../../../../examples/ts/nested-if-multi-reassign/StackTrackerRepro.runar.ts'),
    'utf8',
  );
  const fileName = 'StackTrackerRepro.runar.ts';

  // Single-record buf: byte 0 = 0x05 (length prefix), bytes 1..5 = 0xaa*5 (payload).
  // Bytes 6..15 = 0xbb*10 (would parse as negative-length record; iter 1+ MUST be skipped).
  const BUF = '05aaaaaaaaaabbbbbbbbbbbbbbbbbbbb';
  const TARGET_ITER0 = '05aaaaaaaaaa';

  it('count=1 with target matching iter 0: interpreter and compiled agree (success)', () => {
    const interp = TestContract.fromSource(src, {}, fileName);
    const interpResult = interp.call('walk', { buf: BUF, count: 1n, target: TARGET_ITER0 });

    const compiled = ScriptExecutionContract.fromSource(src, {}, fileName);
    const scriptResult = compiled.execute('walk', [BUF, 1n, TARGET_ITER0]);

    expect(interpResult.success).toBe(true);
    expect(scriptResult.success).toBe(true);
  });

  it('count=0: both fail (found stays false, assert(found) aborts)', () => {
    const interp = TestContract.fromSource(src, {}, fileName);
    const interpResult = interp.call('walk', { buf: BUF, count: 0n, target: TARGET_ITER0 });

    const compiled = ScriptExecutionContract.fromSource(src, {}, fileName);
    const scriptResult = compiled.execute('walk', [BUF, 0n, TARGET_ITER0]);

    expect(interpResult.success).toBe(false);
    expect(scriptResult.success).toBe(false);
  });

  it('count=1 with non-matching target: both fail', () => {
    const interp = TestContract.fromSource(src, {}, fileName);
    const interpResult = interp.call('walk', { buf: BUF, count: 1n, target: '05bbbbbbbbbb' });

    const compiled = ScriptExecutionContract.fromSource(src, {}, fileName);
    const scriptResult = compiled.execute('walk', [BUF, 1n, '05bbbbbbbbbb']);

    expect(interpResult.success).toBe(false);
    expect(scriptResult.success).toBe(false);
  });

  it('count=8 with 8 valid records: interpreter and compiled agree (full unroll, target on iter 7)', () => {
    // 8 single-byte-payload records: each is 0x01<XX>. High bit of XX kept clear
    // so bin2num doesn't parse a negative length. 8 records × 2 bytes = 16 bytes.
    const buf8 = '0111' + '0122' + '0133' + '0144' + '0155' + '0166' + '0177' + '0178';
    const targetIter7 = '0178';

    const interp = TestContract.fromSource(src, {}, fileName);
    const interpResult = interp.call('walk', { buf: buf8, count: 8n, target: targetIter7 });

    const compiled = ScriptExecutionContract.fromSource(src, {}, fileName);
    const scriptResult = compiled.execute('walk', [buf8, 8n, targetIter7]);

    expect(interpResult.success).toBe(true);
    expect(scriptResult.success).toBe(true);
  });
});
