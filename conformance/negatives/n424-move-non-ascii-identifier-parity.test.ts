import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex, REPO } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-424 — N-407's contract on `.runar.move`: a non-ASCII letter in an
 * identifier, or a non-ASCII whitespace character between tokens, is refused
 * by EVERY tier with the TS reference's diagnostic
 * `:<line>:<col>: Unexpected character '<c>'` at that character.
 *
 * Before the fix (base matrix: remediation-logs/N-407/matrix.txt, `.move`):
 * python and java accepted `diffé` / `édiff` (str.isalpha /
 * Character.isLetter) and rust accepted U+00A0 / U+2003 between tokens
 * (char::is_whitespace). ts, go, zig and ruby already refused.
 *
 * What this proves: for `é` at the start and in the middle of a local's name
 * and for U+00A0 / U+2003 between two tokens, every tier rejects with the
 * shared diagnostic at the FIRST offending character; a comment containing
 * non-ASCII text is still accepted and every tier compiles it to the hex of
 * the unmodified template, identical on all tiers.
 * What it does NOT prove: the file-name prefix or any later diagnostic; other
 * non-ASCII characters (other scripts, combining marks, U+FEFF, U+2028);
 * non-ASCII inside string literals; ASCII control whitespace (form feed,
 * vertical tab); columns after an earlier non-ASCII character on the line.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n424-'));

interface Surface {
  ext: string;
  path: string;
  /** Text around the first `+` of the template, with the space before it. */
  wsNeedle: string;
  comment: string;
  /** The line the non-ASCII comment is inserted before. */
  commentBefore: string;
}

const SURFACES: Surface[] = [
  { ext: 'move', path: 'examples/move/arithmetic/Arithmetic.runar.move', wsNeedle: 'a + b;', comment: '//', commentBefore: '        let diff' },
];

let n = 0;
function write(file: string, text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, file);
  writeFileSync(p, text);
  return p;
}

/** `:<line>:<col>: ` of the first occurrence of `c` (line 1-based, column 0-based). */
function at(text: string, c: string): string {
  const off = text.indexOf(c);
  if (off < 0) throw new Error(`template does not contain ${JSON.stringify(c)}`);
  const lines = text.slice(0, off).split('\n');
  return `:${lines.length}:${lines[lines.length - 1]!.length}: `;
}

/** Replace the space before the template's first `+` (or the `(` of `.plus(`) with `ws`. */
function withWs(s: Surface, base: string, ws: string): string {
  const repl = s.wsNeedle.startsWith('a.plus(') ? s.wsNeedle.replace('(', `(${ws}`) : s.wsNeedle.replace(' +', `${ws}+`);
  return base.replace(s.wsNeedle, repl);
}

describe('N-424 non-ASCII letters in identifiers and non-ASCII whitespace — every tier vs the TS reference', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const s of SURFACES) {
    const base = readFileSync(join(REPO, s.path), 'utf8');
    const file = `Arithmetic.runar.${s.ext}`;
    if (!/\bdiff\b/.test(base) || !base.includes(s.wsNeedle) || !base.includes(s.commentBefore)) {
      throw new Error(`${s.path} no longer has the shape this test edits`);
    }
    if (/[^\x00-\x7f]/.test(base)) throw new Error(`${s.path} already contains non-ASCII text`);

    const cases: Array<[string, string, string]> = [
      ['é inside an identifier', base.replace(/\bdiff\b/g, 'diffé'), 'é'],
      ['é starting an identifier', base.replace(/\bdiff\b/g, 'édiff'), 'é'],
      ['U+00A0 between tokens', withWs(s, base, ' '), ' '],
      ['U+2003 between tokens', withWs(s, base, ' '), ' '],
    ];
    for (const [what, text, c] of cases) {
      if (text === base) throw new Error(`${what} did not modify ${s.path}`);
      const path = write(file, text);
      const want = `${at(text, c)}Unexpected character '${c}'`;
      for (const tier of TIERS) {
        it(`${tier.id} refuses ${what} on .${s.ext} with the shared diagnostic`, () => {
          const j = judge(tier, path);
          expect(j.verdict).toBe('rejected');
          expect(j.diag).toContain(want);
        });
      }
    }

    const controlPath = write(file, base);
    const commentText = base.replace(
      s.commentBefore,
      `${s.commentBefore.match(/^\s*/)![0]}${s.comment} café ü — ñ\n${s.commentBefore}`,
    );
    const commentPath = write(file, commentText);
    it(`every tier compiles the unmodified .${s.ext} template, and the one with a non-ASCII comment, to the same hex`, () => {
      const hexes = TIERS.map((t) => compileHex(t, controlPath));
      for (const h of hexes) expect(h).toBe(hexes[0]);
      for (const t of TIERS) expect(compileHex(t, commentPath)).toBe(hexes[0]);
    });
  }
});
