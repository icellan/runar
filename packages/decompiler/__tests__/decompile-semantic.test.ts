/**
 * I5 — `decompile({ semantic: true })` end-to-end + no-regression guarantee.
 *
 * With the flag on, a foreign script that would otherwise hit the raw_script
 * floor is upgraded to a structured `semantic` result carrying a fidelity map.
 * With the flag off, behaviour is unchanged (raw_script).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { hexToBytes } from 'runar-testing';
import { decompile } from '../src/index.js';

const ftkHex = readFileSync(
  new URL('./fixtures/ftk-demo.hex', import.meta.url),
  'utf8',
).trim();
const bytes = hexToBytes(ftkHex);

describe('decompile — semantic mode (I5)', () => {
  it('upgrades the FTK foreign script to a structured semantic result', () => {
    const res = decompile(bytes, { semantic: true });
    expect(res.recoveryPath).toBe('semantic');
    expect(res.fidelity).toBeDefined();
    expect(res.fidelity!.summary.totalBytes).toBe(1428);
    expect(res.fidelity!.summary.coveredBytes).toBe(1428);
    expect(res.source).toContain('assert(checkSig(sig, pubKey))');
    expect(res.source).toContain('constructor(ownerPkh: ByteString)');
    expect(res.source).toContain('extends UnsafeSmartContract');
    // displayed source is now the native-if structured view
    expect(res.source).toMatch(/\n {4,}if \(/);
    expect(res.source).toContain('} else {');
    expect(res.source).toMatch(/private \w+\(\): void \{/);
    expect(res.source.toLowerCase()).toContain('semantic');
    // byte-exact companion is retained and recompiles byte-identical
    expect(res.byteExactSource).toBeDefined();
    expect(res.byteExactSource).toContain('Compiling reconstruction');
    expect(res.ok).toBe(true);
    // the decompiler CHECKED the displayed source: FTK's native-if view does
    // not recompile identical, so the verdict is a divergence warning
    expect(res.sourceByteIdentical).toBe(false);
    expect(res.source).toContain('⚠ WARNING');
    expect(res.source).toContain('does NOT reproduce');
  });

  it('without the flag, the FTK script still falls to raw_script (no regression)', () => {
    const res = decompile(bytes);
    expect(res.recoveryPath).toBe('raw_script');
    expect(res.fidelity).toBeUndefined();
  });
});
