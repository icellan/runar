/**
 * R-243 (GK-DOC-002): the SDK usage references described an 8-contract world.
 *
 * All three said "all 8 Rúnar contracts". Eight is the right count for what
 * those files contain — P2PKH, Escrow, Counter, FungibleToken, NFT, Auction,
 * OraclePriceFeed, CovenantVault — but "all" was wrong about the repository:
 * the catalogue is roughly eighty contract directories per tree, across nine
 * surfaces. A reader taking the word literally would think they had seen
 * everything.
 *
 * This test ties the claim to the two things it can be wrong about: the number
 * of examples the file actually contains, and whether it claims to be the whole
 * catalogue.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const USAGE_DIR = join(ROOT, 'examples', 'sdk-usage');

describe('R-243: the SDK usage references do not claim to be the catalogue', () => {
  it('none of them says "all N contracts"', () => {
    const offenders: string[] = [];
    for (const file of readdirSync(USAGE_DIR)) {
      const text = readFileSync(join(USAGE_DIR, file), 'utf8');
      text.split('\n').forEach((line, i) => {
        // The corrected comments quote the old wording; skip those.
        if (/used to say/.test(line)) return;
        if (/\ball \d+ Rúnar\b/.test(line) || /\ball \d+ contract/.test(line)) {
          offenders.push(`${file}:${i + 1}: ${line.trim()}`);
        }
      });
    }
    expect(
      offenders,
      'these claim to cover every Rúnar contract; the catalogue is far larger ' +
        '(see examples/README.md)',
    ).toEqual([]);
  });

  it('the catalogue really is much larger than eight', () => {
    // The fact that makes the old wording wrong. If the catalogue ever shrank
    // to eight, this note should be revisited rather than left in place.
    const tsExamples = readdirSync(join(ROOT, 'examples', 'ts')).filter((d) =>
      statSync(join(ROOT, 'examples', 'ts', d)).isDirectory(),
    );
    expect(tsExamples.length).toBeGreaterThan(20);
  });
});
