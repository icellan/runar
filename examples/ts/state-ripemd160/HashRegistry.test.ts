import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'HashRegistry.runar.ts'), 'utf8');

const initialHash = '01020304050607080910111213141516171819ff';
const nextHash = 'a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4';

describe('HashRegistry', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { currentHash: initialHash });
    expect(c.state.currentHash).toBe(initialHash);
  });

  it('overwrites the stored hash on update', () => {
    const c = TestContract.fromSource(source, { currentHash: initialHash });
    const result = c.call('update', { newHash: nextHash });
    expect(result.success).toBe(true);
    expect(c.state.currentHash).toBe(nextHash);
  });
});
