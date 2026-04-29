import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P384Primitives.runar.sol'), 'utf8');
const FILE_NAME = 'P384Primitives.runar.sol';

// Compile-check only, mirroring the peer Zig/Go suites — constructing real
// P-384 points belongs in the runar-sdk tier.
const ZERO_PT_HEX = '00'.repeat(96);

describe('P384Primitives (Solidity)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { expectedPoint: ZERO_PT_HEX }, FILE_NAME);
    expect(c.state.expectedPoint).toBe(ZERO_PT_HEX);
  });
});
