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
 * diagnostic; every `accept` shape compiles without it; the per-method (not
 * per-path) residual is pinned.
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

/** The D18 diagnostic's method-independent tail, to spot it on any method. */
const D18_TAIL = corpus.error_template.slice(corpus.error_template.indexOf(' writes contract state'));

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

  // Documented residual: the rule is per METHOD. A write on a path whose
  // sibling branch calls addOutput is accepted even though the raw-output
  // branch drops the write. Pinned so a future path-sensitive rule flips it
  // knowingly.
  it('residual: accepts a write on a raw-output branch when another branch calls addOutput', () => {
    const src = `import { StatefulSmartContract, ByteString } from 'runar-lang';

class Residual extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }

  public pay(script: ByteString, flag: bigint) {
    if (flag > 0n) {
      this.addOutput(1000n, this.count + 1n);
    } else {
      this.count = this.count + 1n;
      this.addRawOutput(1000n, script);
    }
  }
}
`;
    const r = compile(src, { fileName: 'Residual.runar.ts' });
    expect(bySeverity(r, 'error').filter((m) => m.includes(D18_TAIL))).toEqual([]);
  });
});
