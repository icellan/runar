import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P256Primitives.runar.sol'), 'utf8');
const FILE_NAME = 'P256Primitives.runar.sol';

// Mirrors the peer Zig/Go P256Primitives suites: TestContract.fromSource is
// the compile-check (parse → validate → typecheck → ANF → stack → emit).
const ZERO_PT_HEX = '00'.repeat(64);

describe('P256Primitives (Solidity)', () => {
  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { expectedPoint: ZERO_PT_HEX }, FILE_NAME);
    expect(c.state.expectedPoint).toBe(ZERO_PT_HEX);
  });
});
