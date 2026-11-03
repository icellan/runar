/**
 * N-202: the source path bounds the PRODUCT of nested loop counts, not just
 * each loop's own count.
 *
 * `extractLoopShape` (CL-BUG-088) caps one `for` at MAX_LOOP_COUNT (10,000).
 * Two loops of 9,000, one inside the other, each passed that cap while the
 * unrolled work was 81,000,000 iterations: the compiler ran with no diagnostic
 * until it was killed. F-283 already refuses the same nest on the --ir path
 * ("... nested inside an enclosing loop of total count E, producing T total
 * iterations ..."), so before this fix a source contract could compile while
 * its own emitted IR was refused on replay.
 *
 * Every compile runs in a child process behind a timeout, so a regression is a
 * test failure, never a hung worker.
 *
 * Proves: on the TS source path, a nest whose product passes 10,000 is refused
 * with the shared product diagnostic, including when the inner loop sits in an
 * if arm (the bound follows the if's sub-context) and three levels deep; the
 * 9,000 x 9,000 nest is refused well inside the timeout; a nest of exactly
 * 10,000 and two sequential loops still compile.
 * Does not prove: other tiers (conformance/negatives/n202-nested-loop-product-
 * parity.test.ts does that), or loops reached through a private method call
 * that stack lowering inlines later — the bound is per-method syntactic
 * nesting in ANF, the same rule the --ir loaders apply.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const TSX = resolve(HERE, '../../../../node_modules/.bin/tsx');
const CHILD = resolve(HERE, '__fixtures__/nested-loop-product-child.ts');

/** Watchdog for the child compile, in milliseconds. */
const WATCHDOG_MS = 30_000;

interface ChildOutcome {
  success: boolean;
  diagnostics: string[];
}

function compileInChild(...args: string[]): ChildOutcome {
  const res = spawnSync(TSX, [CHILD, ...args], {
    encoding: 'utf8',
    timeout: WATCHDOG_MS,
    env: { ...process.env, NODE_OPTIONS: '--max-old-space-size=512' },
  });
  if (res.error !== undefined || res.signal !== null) {
    throw new Error(
      `${args.join(' ')}: the child compile did not terminate within ${WATCHDOG_MS}ms ` +
        `(signal ${String(res.signal)}) — the nested loops are being unrolled unbounded`,
    );
  }
  if (res.status !== 0) {
    throw new Error(
      `${args.join(' ')}: the child compile exited ${String(res.status)} instead of ` +
        `reporting a diagnostic.\nstderr: ${res.stderr.slice(-2000)}`,
    );
  }
  return JSON.parse(res.stdout) as ChildOutcome;
}

function productMessage(count: number, enclosing: number): string {
  return (
    `For loop unrolls to ${count} iterations nested inside an enclosing loop of total count ` +
    `${enclosing}, producing ${count * enclosing} total iterations, exceeding the maximum loop ` +
    `count of 10000.`
  );
}

describe('nested loop product bound on the source path (N-202)', () => {
  it('refuses 101 x 100 with the shared product diagnostic', () => {
    const out = compileInChild('nested', '101', '100');
    expect(out.success).toBe(false);
    expect(out.diagnostics).toContain(productMessage(100, 101));
  });

  it('refuses 9000 x 9000 instead of unrolling 81,000,000 iterations', () => {
    const out = compileInChild('nested', '9000', '9000');
    expect(out.success).toBe(false);
    expect(out.diagnostics).toContain(productMessage(9000, 9000));
  });

  it('carries the enclosing count through an if arm', () => {
    const out = compileInChild('if-arm', '101', '100');
    expect(out.success).toBe(false);
    expect(out.diagnostics).toContain(productMessage(100, 101));
  });

  it('multiplies every level of a three-deep nest', () => {
    const out = compileInChild('triple', '10', '10', '101');
    expect(out.success).toBe(false);
    expect(out.diagnostics).toContain(productMessage(101, 100));
  });

  it('still compiles a nest of exactly MAX_LOOP_COUNT (100 x 100)', () => {
    const out = compileInChild('nested', '100', '100');
    expect(out.diagnostics).toEqual([]);
    expect(out.success).toBe(true);
  });

  it('does not multiply sequential loops (101 then 100)', () => {
    const out = compileInChild('sequential', '101', '100');
    expect(out.diagnostics).toEqual([]);
    expect(out.success).toBe(true);
  });
});
