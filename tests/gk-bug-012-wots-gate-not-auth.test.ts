/**
 * GK-BUG-012: StatefulWOTSGate's `advance(msg, sig, wotsPubKey)` takes the
 * WOTS+ public key as a spender-supplied argument, so any spender can mint a
 * fresh key, sign, and advance the counter. That is deliberate: the contract
 * is a composition fixture (stateful covenant + WOTS+ verify in one script,
 * GAP-407), recorded as such in conformance/script_execution_test.go and
 * sdk-output/coverage-allowlist.json. But the TS copy said "state mutation is
 * gated on a WOTS+ one-time signature", and the other eight copies (and the
 * decompiler's embedded TS template) carried no warning at all. Someone
 * copying it as an auth pattern gets no authorization.
 *
 * Proves: all nine copies and the decompiler template state that it is NOT an
 * authorization gate, and the TS copy no longer says it is gated.
 * Does not prove: anything about the script (comment-only change).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p: string) => readFileSync(join(ROOT, p), 'utf8');
const MARK = 'NOT AN AUTHORIZATION GATE';

const COPIES = [
  'examples/ts/stateful-wots-gate/StatefulWOTSGate.runar.ts',
  'examples/sol/stateful-wots-gate/StatefulWOTSGate.runar.sol',
  'examples/move/stateful-wots-gate/StatefulWOTSGate.runar.move',
  'examples/go/stateful-wots-gate/StatefulWOTSGate.runar.go',
  'examples/rust/stateful-wots-gate/StatefulWOTSGate.runar.rs',
  'examples/python/stateful-wots-gate/StatefulWOTSGate.runar.py',
  'examples/zig/stateful-wots-gate/StatefulWOTSGate.runar.zig',
  'examples/ruby/stateful-wots-gate/StatefulWOTSGate.runar.rb',
  'examples/java/src/main/java/runar/examples/stateful-wots-gate/StatefulWOTSGate.runar.java',
];

describe('GK-BUG-012: StatefulWOTSGate is labelled a fixture, not an auth gate', () => {
  it('source.json still points at exactly these nine copies', () => {
    const src = JSON.parse(read('conformance/tests/stateful-wots-gate/source.json')) as { sources: Record<string, string> };
    const declared = Object.values(src.sources).map((p) => p.replace(/^(\.\.\/)+/, '')).sort();
    expect(declared).toEqual([...COPIES].sort());
  });

  for (const p of COPIES) {
    it(`${p} carries the warning`, () => {
      const text = read(p);
      expect(text).toContain(MARK);
      expect(text).toMatch(/wotsPubKey is a spender-supplied witness/);
      expect(text).not.toMatch(/gated on a WOTS\+/);
    });
  }

  it('the decompiler template embeds the corrected TS source', () => {
    const m = JSON.parse(read('packages/decompiler/templates-data.json')) as { entries: Array<{ origin: string; source: string }> };
    const e = m.entries.find((x) => x.origin.includes('stateful-wots-gate'));
    expect(e, 'no stateful-wots-gate template').toBeDefined();
    expect(e!.source).toBe(read(COPIES[0]!));
  });
});
