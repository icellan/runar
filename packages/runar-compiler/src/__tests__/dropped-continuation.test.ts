import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { compile } from '../index.js';

/**
 * D18 (dropped state continuation), TypeScript reference tier. The corpus is
 * the cross-tier one in conformance/negatives/dropped-continuation-cases.json,
 * shared with the other six tiers' unit tests and
 * conformance/negatives/gk-frontend-parity.test.ts.
 *
 * Proves, for this tier: every `refuse` shape fails with the shared
 * diagnostic (per path: see the corpus comment); every `accept` shape compiles
 * without it.
 * Does not prove: anything about the other six tiers, or the --ir path
 * (conformance/negatives/ir-release-trap.test.ts carries that).
 */

const REPO = resolve(__dirname, '../../../..');
interface Case { name: string; file: string; src: string; error?: string }
const corpus = JSON.parse(
  readFileSync(join(REPO, 'conformance/negatives/dropped-continuation-cases.json'), 'utf8'),
) as { refuse: Case[]; accept: Case[]; error_template: string };

const bySeverity = (r: ReturnType<typeof compile>, s: string): string[] =>
  r.diagnostics.filter((d) => d.severity === s).map((d) => d.message);


describe('D18: a state write with no state continuation is refused', () => {
  for (const c of corpus.refuse) {
    it(`refuses ${c.name}`, () => {
      const r = compile(c.src, { fileName: c.file });
      expect(r.success).toBe(false);
      expect(bySeverity(r, 'error')).toContain(c.error);
    });
  }
  for (const c of corpus.accept) {
    it(`accepts ${c.name}`, () => {
      const r = compile(c.src, { fileName: c.file });
      expect(bySeverity(r, 'error')).toEqual([]);
      expect(r.success).toBe(true);
    });
  }
});
