/**
 * N-486: the evm-guest fixture README documented proof.postcard as 140778 B
 * after the file had been regenerated at 326909 B.
 *
 * Proves: every `N B` size the README's Files table states for proof.postcard
 * equals the committed file's byte length. Does not prove: that the proof is
 * valid (sp1fri's TestVerifyEvmGuest does) or that other docs are fresh.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const dir = join(__dirname, 'vectors', 'sp1', 'fri', 'evm-guest');

describe('N-486 evm-guest README size claim', () => {
  it('documents the actual proof.postcard size', () => {
    const readme = readFileSync(join(dir, 'README.md'), 'utf8');
    const row = readme.split('\n').find((l) => l.startsWith('| `proof.postcard`'));
    expect(row, 'README has a proof.postcard row').toBeDefined();
    const m = /\|\s*(\d+)\s*B\s*\|/.exec(row!);
    expect(m, 'row states a size in bytes').not.toBeNull();
    expect(Number(m![1])).toBe(statSync(join(dir, 'proof.postcard')).size);
  });
});
