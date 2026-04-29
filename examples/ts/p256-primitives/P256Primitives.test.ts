import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P256Primitives.runar.ts'), 'utf8');

// P256Primitives.runar.ts exercises NIST P-256 builtins (p256Mul, p256Add,
// p256MulGen). Constructing real P-256 points from native TS duplicates work
// covered by the runar-sdk tier — peer Zig/Go suites also keep this fixture
// at frontend coverage. TestContract.fromSource itself is the compile-check
// (parse → validate → typecheck → ANF → stack → emit).
const ZERO_PT_HEX = '00'.repeat(64);

describe('P256Primitives', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { expectedPoint: ZERO_PT_HEX });
    expect(c.state.expectedPoint).toBe(ZERO_PT_HEX);
  });
});
