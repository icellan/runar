import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { compile } from '../index.js';

/**
 * #199 (release-trap warning), TypeScript reference tier. The corpus is the
 * cross-tier one in conformance/negatives/release-trap-cases.json, shared with
 * the other six tiers' unit tests and
 * conformance/negatives/gk-frontend-parity.test.ts.
 *
 * Proves, for this tier: every `warn` shape compiles (the warning is
 * non-fatal) and carries the shared contract-level warning; no `nowarn` shape
 * carries it.
 * Does not prove: anything about the other six tiers.
 */

const REPO = resolve(__dirname, '../../../..');
interface Case { name: string; file: string; src: string; warning?: string; warning_absent?: string }
const corpus = JSON.parse(
  readFileSync(join(REPO, 'conformance/negatives/release-trap-cases.json'), 'utf8'),
) as { warn: Case[]; nowarn: Case[] };

const bySeverity = (r: ReturnType<typeof compile>, s: string): string[] =>
  r.diagnostics.filter((d) => d.severity === s).map((d) => d.message);

describe('#199: a stateful contract that can never release its satoshis warns', () => {
  for (const c of corpus.warn) {
    it(`warns on ${c.name}`, () => {
      const r = compile(c.src, { fileName: c.file });
      expect(bySeverity(r, 'error')).toEqual([]);
      expect(r.success).toBe(true);
      expect(bySeverity(r, 'warning')).toContain(c.warning);
    });
  }
  for (const c of corpus.nowarn) {
    it(`does not warn on ${c.name}`, () => {
      const r = compile(c.src, { fileName: c.file });
      expect(bySeverity(r, 'error')).toEqual([]);
      expect(bySeverity(r, 'warning')).not.toContain(c.warning_absent);
    });
  }
});
