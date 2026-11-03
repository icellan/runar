import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-019 — a terminated quoted literal ("..." or '...') on `.runar.sol` and
 * `.runar.move` is refused at parse by all seven tiers, with the TS
 * reference's diagnostic `Unexpected character '<quote>'` at the opening
 * quote's line and column.
 *
 * Before the fix the TS reference refused (neither surface has a quoted
 * literal; the documented byte literal is `0x...`), while go, rust, python,
 * zig and java accepted `"cafe"` as a ByteString (and ruby did on .sol).
 * Ruby's .move tokenizer skipped the quotes silently, so the source failed
 * later with "Undefined variable 'cafe'" or a garbage parse error, and Zig
 * only rejected the escaped form at stack lowering.
 *
 * What this proves:
 *   - for plain, empty and escaped literals in double and single quotes on
 *     each of .sol and .move, every available tier rejects the source and its
 *     diagnostic carries `:<line>:<col>: Unexpected character '<q>'` for the
 *     opening quote;
 *   - the `0xcafe` hex literal control compiles to the same hex on every tier;
 *   - an UNTERMINATED quote still gets the F-011 diagnostic on every tier.
 * What it does NOT prove:
 *   - the position prefix beyond `:line:col:` (file naming differs per tier),
 *     or the diagnostics that follow the first one (TS also re-tokenizes the
 *     literal's contents; the other tiers swallow it);
 *   - any other surface (.ts/.py/.rb/.go/.rs/.zig/.java have their own string
 *     handling).
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n019-'));

const sol = (lit: string) => `pragma runar ^0.1.0;

contract S is SmartContract {
    ByteString immutable target;

    constructor(ByteString _target) {
        target = _target;
    }

    function unlock(ByteString x) public {
        require(x == ${lit});
    }
}
`;
// The literal is on line 11, column 21 (0-based) of the .sol template.
const SOL_AT = ':11:21: ';

const move = (lit: string) => `module M {
    use runar::types::{ByteString};

    struct M {
        target: ByteString,
    }

    public fun unlock(contract: &M, x: ByteString) {
        assert!(x == ${lit}, 0);
    }
}
`;
// The literal is on line 9, column 21 (0-based) of the .move template.
const MOVE_AT = ':9:21: ';

let n = 0;
function write(file: string, text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, file);
  writeFileSync(p, text);
  return p;
}

const LITERALS: Array<[string, string, string]> = [
  ['double-quoted', '"cafe"', '"'],
  ['empty double-quoted', '""', '"'],
  ['escaped double-quoted', '"ca\\"fe"', '"'],
  ['single-quoted', "'cafe'", "'"],
  ['empty single-quoted', "''", "'"],
  ['escaped single-quoted', "'ca\\'fe'", "'"],
];

const SURFACES: Array<[string, string, (l: string) => string, string]> = [
  ['.sol', 'S.runar.sol', sol, SOL_AT],
  ['.move', 'M.runar.move', move, MOVE_AT],
];

describe('N-019 terminated quoted literal — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [surface, file, mk, at] of SURFACES) {
    for (const [name, lit, q] of LITERALS) {
      const path = write(file, mk(lit));
      for (const tier of TIERS) {
        it(`${tier.id} refuses a ${name} literal on ${surface} with the shared diagnostic`, () => {
          const j = judge(tier, path);
          expect(j.verdict).toBe('rejected');
          expect(j.diag).toContain(`${at}Unexpected character '${q}'`);
        });
      }
    }

    const hexPath = write(file, mk('0xcafe'));
    it(`every tier compiles the 0xcafe control on ${surface} to the same hex`, () => {
      const hexes = TIERS.map((t) => compileHex(t, hexPath));
      for (const h of hexes) expect(h).toBe(hexes[0]);
    });

    const openPath = write(file, mk('"cafe'));
    for (const tier of TIERS) {
      it(`${tier.id} still gives the F-011 diagnostic for an unterminated quote on ${surface}`, () => {
        const j = judge(tier, openPath);
        expect(j.verdict).toBe('rejected');
        expect(j.diag).toContain(`${at}unterminated string literal`);
      });
    }
  }
});
