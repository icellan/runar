import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * N-321 — typecheck diagnostics must not echo an unbounded type text.
 *
 * A 1 MB identifier type annotation used to produce ~1 MB diagnostics (twice).
 * Every tier now caps a typecheck message at 1024 characters and appends
 * `...(N more bytes elided)`.
 *
 * Proves: a 1 MB flat type name yields diagnostics each <= 1024 chars + marker
 * and an ordinary type is echoed verbatim. Does not prove: the other six tiers
 * (conformance/negatives/n321-diagnostic-type-echo-parity.test.ts) nor each
 * individual echo site (the cap sits at the diagnostic sink).
 */
const HEAD = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint) {\n let q: {T} = a;\n assert(q == this.t);\n }\n}\n";

function messages(typ: string): string[] {
  const r = compile(HEAD.replace('{T}', typ), { fileName: 'P.runar.ts' });
  expect(r.success).toBe(false);
  return r.diagnostics.map((d) => d.message);
}

describe('N-321: typecheck diagnostics elide huge type text', () => {
  it('a 1 MB type name is elided with a marker', () => {
    const msgs = messages('T'.repeat(1 << 20));
    const echoing = msgs.filter((m) => m.includes('TTTT'));
    expect(echoing.length).toBeGreaterThan(0);
    for (const m of echoing) {
      expect(m.length).toBeLessThan(1100);
      expect(m).toMatch(/\.\.\.\(\d+ more bytes elided\)$/);
    }
  });

  it('an ordinary type is echoed verbatim', () => {
    expect(messages('ByteString').join('\n')).toContain("'ByteString'");
  });
});
