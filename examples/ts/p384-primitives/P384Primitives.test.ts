import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P384Primitives.runar.ts'), 'utf8');

// See examples/ts/p256-primitives for the rationale; TestContract.fromSource
// is the compile-check, and the interpreter's P-384 ops are mocked to zero
// bytes so we can also exercise the call path with an all-zero expectedPoint.
const ZERO_PT_HEX = '00'.repeat(96); // 96-byte P384Point

describe('P384Primitives', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { expectedPoint: ZERO_PT_HEX });
    expect(c.state.expectedPoint).toBe(ZERO_PT_HEX);
  });
});
