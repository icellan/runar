/**
 * Regression tests for CL-BUG-088 / R-009: the unrolled loop iteration count is
 * computed as an arbitrary-precision integer and then narrowed to a machine
 * integer, with nothing bounding the magnitude first.
 *
 * In this tier the narrowing is `Math.max(0, Number(count))`. `Number(bigint)`
 * silently loses precision above 2^53 and becomes `Infinity` above ~1.8e308, so
 * the unroll loop below it tries to run an astronomically large — or literally
 * infinite — number of iterations. Reproduced at HEAD: bounds of 2^63 and
 * 2^64+10 both drive the compiler into `JavaScript heap out of memory`, never a
 * diagnostic.
 *
 * The second half of the contract is the ceiling itself. `MAX_LOOP_COUNT`
 * (10000) existed nowhere in this tier outside a test-local constant in
 * ir-loader.test.ts, so a source contract could ask for any unroll count at all.
 * A bound of 10001 compiled happily.
 *
 * What these tests pin: an out-of-range or over-ceiling loop bound is a
 * compile-time diagnostic, and a valid loop still compiles to the exact bytes it
 * produced before the guard existed.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from '../index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const TSX = resolve(HERE, '../../../../node_modules/.bin/tsx');
const CHILD = resolve(HERE, '__fixtures__/loop-bound-child.ts');

/** Watchdog for the child compile, in milliseconds. */
const WATCHDOG_MS = 30_000;

function loopBoundSource(bound: string): string {
  return `import { SmartContract, assert } from 'runar-lang';

export class LoopBound extends SmartContract {
  constructor() { super(); }

  public unlock(x: bigint): void {
    let acc: bigint = 0n;
    for (let i = 0n; i < ${bound}n; i++) {
      acc = acc + i;
    }
    assert(acc === x);
  }
}
`;
}

interface ChildOutcome {
  success: boolean;
  script: string | null;
  diagnostics: string[];
}

/**
 * Compile the given bound in a child process with a hard timeout and a capped
 * old-generation heap. A regression fails fast with a readable message instead
 * of wedging the vitest worker or eating the machine's memory.
 */
function compileInChild(bound: string): ChildOutcome {
  const res = spawnSync(TSX, [CHILD, bound], {
    encoding: 'utf8',
    timeout: WATCHDOG_MS,
    env: { ...process.env, NODE_OPTIONS: '--max-old-space-size=512' },
  });

  if (res.error !== undefined || res.signal !== null) {
    throw new Error(
      `bound ${bound}: the child compile did not terminate within ${WATCHDOG_MS}ms ` +
        `(signal ${String(res.signal)}) — the narrowed count is still driving loop unrolling`,
    );
  }
  if (res.status !== 0) {
    throw new Error(
      `bound ${bound}: the child compile exited ${String(res.status)} instead of ` +
        `reporting a diagnostic — likely heap exhaustion.\nstderr: ${res.stderr.slice(-2000)}`,
    );
  }
  return JSON.parse(res.stdout) as ChildOutcome;
}

function expectRejected(outcome: ChildOutcome, label: string): void {
  expect(
    outcome.success,
    `bound ${label}: expected a compile diagnostic, got a successful compile (script ${String(outcome.script)})`,
  ).toBe(false);
  expect(
    outcome.diagnostics.some((m) => m.toLowerCase().includes('loop')),
    `bound ${label}: expected a diagnostic mentioning the loop bound, got ${JSON.stringify(outcome.diagnostics)}`,
  ).toBe(true);
}

describe('loop bound narrowing (CL-BUG-088)', () => {
  // Control. These hex strings were captured before the guard existed; if a
  // guard moves them, the guard is not byte-neutral and that is a codegen
  // regression, not a fix.
  it.each([
    { bound: '3', hex: '537c9c' },
    { bound: '10', hex: '012d7c9c' },
  ])('still compiles a bound of $bound byte-identically', ({ bound, hex }) => {
    for (const disableConstantFolding of [false, true]) {
      const res = compile(loopBoundSource(bound), {
        fileName: 'LoopBound.runar.ts',
        disableConstantFolding,
      });
      expect(res.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
      expect(res.success).toBe(true);
      expect(res.artifact?.script).toBe(hex);
    }
  });

  it('rejects a bound of 2^63 instead of losing precision', () => {
    expectRejected(compileInChild('9223372036854775808'), '2^63');
  });

  it('rejects a bound of 2^64 + 10 instead of losing precision', () => {
    const outcome = compileInChild('18446744073709551626');
    expectRejected(outcome, '2^64+10');
    // Belt and braces: whatever happens, it must not silently agree with the
    // `i < 10n` contract.
    expect(outcome.script).not.toBe('012d7c9c');
  });

  it('rejects a bound of 10^20 without hanging', () => {
    expectRejected(compileInChild('100000000000000000000'), '10^20');
  });

  // The ceiling half of the fix: MAX_LOOP_COUNT must apply on the SOURCE path,
  // not only when ANF IR arrives pre-built. 10001 fits every machine integer
  // there is, so no amount of narrowing care stops it — only the ceiling does.
  it('rejects a source loop that unrolls past MAX_LOOP_COUNT', () => {
    const outcome = compileInChild('10001');
    expectRejected(outcome, '10001');
    expect(outcome.diagnostics.join(' ')).toContain('10000');
  });
});
