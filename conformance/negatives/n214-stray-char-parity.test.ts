import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex, REPO } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-214 — a stray character inside a method body is refused by EVERY tier on
 * EVERY surface except `.runar.py` (extends N-020, which fixed Go `.java` and
 * Go/Rust `.rs`). Before N-214, most hand-written tokenizers dropped a
 * character they did not recognise without a word, so `a + § b` compiled
 * exactly as `a + b` (base matrix: remediation-logs/N-214/matrix-base.txt).
 *
 * Every (surface, character, tier) cell is generated; nothing is skipped.
 * What each cell asserts depends on what the character IS on that surface,
 * per the TS reference tokenizer:
 *
 *   'shared'  the character is not a token of the surface: every tier must
 *             refuse with TS's diagnostic `:<line>:<col>: Unexpected character
 *             '<c>'` at the character (line 1-based, column 0-based).
 *   'reject'  the character IS a token of the surface (`@` on .ts/.zig/.java,
 *             `#` on .ts/.rs/.rb, a backtick on .ts/.go), so TS refuses it
 *             with a parser or string-literal diagnostic, not this one: every
 *             tier must reject, the wording is not pinned.
 *   bare `@` on .rb is an ivar sigil with no name: TS lexes a lone `@` token
 *             and refuses `Unexpected token in expression: '@'`; every tier
 *             must give that diagnostic (case-insensitive) at the `@`.
 *
 * The `.ts` surface is parsed by real TypeScript parsers in three tiers (TS:
 * ts-morph, Go: tree-sitter, Rust: swc), whose wording cannot be the shared
 * one ('Invalid character.', 'unparseable', 'TS1109'). On .ts the shared
 * diagnostic is therefore pinned only for the four hand-written .ts
 * tokenizers (python, zig, ruby, java); the three upstream parsers must still
 * reject.
 *
 * What this proves:
 *   - no tier silently drops any of `@`, `§`, a backtick or `#` in a method
 *     body on .ts/.sol/.move/.go/.rs/.zig/.rb/.java;
 *   - where the character is stray, every tier reports TS's diagnostic at the
 *     same line and column (so `§`, two bytes in UTF-8, is reported as one
 *     character at its own column);
 *   - the unmodified template compiles to the same hex on every tier, so each
 *     rejection is about the character and not about the template.
 * What it does NOT prove:
 *   - the file-name prefix of the diagnostic, or the diagnostics after the
 *     first one;
 *   - other characters, characters outside a method body, or non-ASCII
 *     LETTERS (N-407); positions after multi-line comments (N-406);
 *   - `.runar.py`, which N-214 does not own.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n214-'));
const UPSTREAM_TS_PARSERS = ['ts', 'go', 'rust'];

type Kind = 'shared' | 'reject' | 'rb-at';
interface Surface {
  ext: string;
  path: string;
  needle: string;
  rep: string; // `C` marks where the stray character goes
  chars: Record<string, Kind>;
}

const SURFACES: Surface[] = [
  { ext: 'ts', path: 'examples/ts/arithmetic/Arithmetic.runar.ts', needle: 'a + b;', rep: 'a + C b;',
    chars: { '@': 'reject', '§': 'shared', '`': 'reject', '#': 'shared' } },
  { ext: 'sol', path: 'examples/sol/arithmetic/Arithmetic.runar.sol', needle: 'a + b;', rep: 'a + C b;',
    chars: { '@': 'shared', '§': 'shared', '`': 'shared', '#': 'shared' } },
  { ext: 'move', path: 'examples/move/arithmetic/Arithmetic.runar.move', needle: 'a + b;', rep: 'a + C b;',
    chars: { '@': 'shared', '§': 'shared', '`': 'shared', '#': 'shared' } },
  { ext: 'go', path: 'examples/go/arithmetic/Arithmetic.runar.go', needle: 'a + b\n', rep: 'a + C b\n',
    chars: { '@': 'shared', '§': 'shared', '`': 'reject', '#': 'shared' } },
  { ext: 'rs', path: 'examples/rust/arithmetic/Arithmetic.runar.rs', needle: 'a + b;', rep: 'a + C b;',
    chars: { '@': 'shared', '§': 'shared', '`': 'shared', '#': 'reject' } },
  { ext: 'zig', path: 'examples/zig/arithmetic/Arithmetic.runar.zig', needle: 'a + b;', rep: 'a + C b;',
    chars: { '@': 'reject', '§': 'shared', '`': 'shared', '#': 'shared' } },
  { ext: 'rb', path: 'examples/ruby/arithmetic/Arithmetic.runar.rb', needle: 'a + b\n', rep: 'a + C b\n',
    chars: { '@': 'rb-at', '§': 'shared', '`': 'shared', '#': 'reject' } },
  { ext: 'java', path: 'examples/java/src/main/java/runar/examples/arithmetic/Arithmetic.runar.java',
    needle: 'a.plus(b)', rep: 'a.plus(C b)',
    chars: { '@': 'reject', '§': 'shared', '`': 'shared', '#': 'shared' } },
];

let n = 0;
function write(file: string, text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, file);
  writeFileSync(p, text);
  return p;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

describe('N-214 stray character in a method body — every tier, every surface but .py', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const s of SURFACES) {
    const base = readFileSync(join(REPO, s.path), 'utf8');
    const at = base.indexOf(s.needle);
    if (at < 0) throw new Error(`${s.path}: template needle ${JSON.stringify(s.needle)} not found`);
    const file = `Arithmetic.runar.${s.ext}`;

    for (const [c, kind] of Object.entries(s.chars)) {
      const text = base.replace(s.needle, s.rep.replace('C', c));
      const lines = text.slice(0, at + s.rep.indexOf('C')).split('\n');
      const pos = `:${lines.length}:${lines[lines.length - 1]!.length}: `;
      const path = write(file, text);

      for (const tier of TIERS) {
        const pinned =
          kind === 'shared' && !(s.ext === 'ts' && UPSTREAM_TS_PARSERS.includes(tier.id));
        const what = kind === 'rb-at' ? 'TS\'s bare-@ diagnostic' : pinned ? 'the shared diagnostic' : 'a rejection';
        it(`${tier.id} refuses ${JSON.stringify(c)} on .${s.ext} with ${what}`, () => {
          const j = judge(tier, path);
          expect(j.verdict, j.diag).toBe('rejected');
          if (pinned) expect(j.diag).toContain(`${pos}Unexpected character '${c}'`);
          if (kind === 'rb-at') {
            expect(j.diag).toMatch(new RegExp(`${escapeRe(pos)}unexpected token in expression: '@'`, 'i'));
          }
        });
      }
    }

    const controlPath = write(file, base);
    it(`every tier compiles the unmodified .${s.ext} template to the same hex`, () => {
      const hexes = TIERS.map((t) => compileHex(t, controlPath));
      for (const h of hexes) expect(h).toBe(hexes[0]);
    });
  }
});
