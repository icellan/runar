import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'ECUnit.runar.ts'), 'utf8');

// ECUnit.testOps exercises ecMulGen / ecAdd / ecMul / ecNegate / ecOnCurve /
// ecMakePoint / ecEncodeCompressed / len internally — `pubKey` is only stored,
// never used in the verifier. Any opaque ByteString suffices.
describe('ECUnit', () => {
  const opaquePubKey = '03' + '00'.repeat(32); // 33-byte placeholder

  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { pubKey: opaquePubKey });
    expect(c.state.pubKey).toBe(opaquePubKey);
  });

  it('testOps runs all EC builtins on the generator without error', () => {
    const c = TestContract.fromSource(source, { pubKey: opaquePubKey });
    const r = c.call('testOps');
    expect(r.success).toBe(true);
  });
});
