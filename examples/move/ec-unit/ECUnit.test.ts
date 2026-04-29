import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'ECUnit.runar.move'), 'utf8');
const FILE_NAME = 'ECUnit.runar.move';

describe('ECUnit (Move)', () => {
  const opaquePubKey = '03' + '00'.repeat(32);

  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { pubKey: opaquePubKey }, FILE_NAME);
    expect(c.state.pubKey).toBe(opaquePubKey);
  });

  it('testOps runs all EC builtins on the generator without error', () => {
    const c = TestContract.fromSource(source, { pubKey: opaquePubKey }, FILE_NAME);
    expect(c.call('testOps').success).toBe(true);
  });
});
