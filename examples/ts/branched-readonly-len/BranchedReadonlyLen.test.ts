// INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/branched-readonly-len.json
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

/**
 * R-106 — `branched-readonly-len` had no test in any of the nine formats.
 *
 * Both state fields are written on BOTH arms, and one of them is a ByteString
 * whose length differs per arm (the caller's `scratch`, or the literal `3030`).
 * That is the variable-length continuation shape: the writer and the reader of
 * the serialized state have to agree on the width, and they are separate code
 * paths in every tier.
 *
 * The values are what matter, so the values are what this asserts — on both
 * arms, including the arm where the ByteString is caller-controlled and can be
 * longer than the literal the other arm writes.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'BranchedReadonlyLen.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

const hex = (b: unknown) =>
  b instanceof Uint8Array ? Buffer.from(b).toString('hex') : String(b);

function continuation(r: { success: boolean; error?: string; outputs: Record<string, unknown>[] }) {
  expect(r.success, r.error).toBe(true);
  expect(r.outputs.length).toBeGreaterThan(0);
  return r.outputs[0]!;
}

describe('BranchedReadonlyLen (a branch that writes a variable-length field)', () => {
  it('non-empty scratch: count increments and the tag becomes scratch', () => {
    const c = TestContract.fromSource(source, { count: 10n, tag: '00' }, FILE);
    const out = continuation(c.call('spend', { scratch: new Uint8Array([0xaa, 0xbb, 0xcc]) }));
    expect(out.count).toBe(11n);
    expect(hex(out.tag)).toBe('aabbcc');
  });

  it('empty scratch: count decrements and the tag becomes the literal', () => {
    const c = TestContract.fromSource(source, { count: 10n, tag: '00' }, FILE);
    const out = continuation(c.call('spend', { scratch: new Uint8Array([]) }));
    expect(out.count).toBe(9n);
    expect(hex(out.tag)).toBe('3030');
  });

  it('the two arms write DIFFERENT tag widths — the shape the fixture is for', () => {
    const wide = TestContract.fromSource(source, { count: 0n, tag: '00' }, FILE);
    const wideOut = continuation(wide.call('spend', { scratch: new Uint8Array([1, 2, 3, 4, 5]) }));
    const narrow = TestContract.fromSource(source, { count: 0n, tag: '00' }, FILE);
    const narrowOut = continuation(narrow.call('spend', { scratch: new Uint8Array([]) }));
    expect(
      hex(wideOut.tag).length === hex(narrowOut.tag).length,
      'if both arms produced the same width this fixture would stop exercising ' +
        'the variable-length continuation it exists for',
    ).toBe(false);
  });
});
