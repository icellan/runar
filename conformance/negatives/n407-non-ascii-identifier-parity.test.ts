import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex, REPO } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-407 — a non-ASCII letter in an identifier, or a non-ASCII whitespace
 * character between tokens, is refused by EVERY tier on `.runar.sol`, `.go`,
 * `.rs`, `.py`, `.zig`, `.rb` and `.java` with the TS reference's diagnostic
 * `:<line>:<col>: Unexpected character '<c>'` at that character.
 *
 * N-423 (user decision R163) — the same holds on `.runar.ts`. ts-morph,
 * tree-sitter and swc accept ECMAScript's Unicode identifiers and Zs
 * whitespace, so the TS reference, Go and Rust refuse any non-ASCII character
 * outside a comment or string literal in a pre-scan of the source text;
 * Python and Java lex identifiers as ASCII only. Before the fix
 * (remediation-logs/N-407/matrix.txt, the .ts cells): ts, go, rust, python
 * and java accepted `diffé` / `édiff`; ts, go and rust accepted U+00A0 /
 * U+2003 between tokens. Zig and Ruby already refused all four.
 *
 * The TS reference tokenizers for those surfaces take identifiers as
 * [A-Za-z_$]-led ASCII runs and whitespace as exactly ' ', '\t', '\r', '\n'.
 * Before the fix (base matrix: remediation-logs/N-407/matrix.txt):
 *   - python accepted `diffé` / `édiff` on every surface (str.isalpha);
 *   - java accepted them on every surface (Character.isLetter, and javac on
 *     .java);
 *   - go and rust accepted them on .go, .rs and .java (unicode.IsLetter /
 *     char::is_alphabetic, and go/parser on .go);
 *   - rust accepted U+00A0 / U+2003 between tokens on .sol, .go, .rs, .java
 *     and go accepted them on .rs and .java (is_whitespace / unicode.IsSpace);
 *     go refused them on .go but with go/scanner's `illegal character U+00A0`.
 *
 * NOT IN SCOPE:
 *   - `.runar.move`: owned by N-341 (same defect measured in python/java for
 *     identifiers and rust for whitespace).
 *
 * What this proves:
 *   - on each of the seven surfaces, for `é` at the start and in the middle of
 *     a local's name and for U+00A0 / U+2003 between two tokens, every tier
 *     rejects and its diagnostic carries `:<line>:<col>: Unexpected character
 *     '<c>'` at the FIRST offending character (line 1-based, column 0-based);
 *   - a comment containing non-ASCII text (`café ü — ñ`) is still accepted
 *     and changes nothing: every tier compiles it to the hex of the unmodified
 *     template, which in turn is the same on every tier.
 * What it does NOT prove:
 *   - the file-name prefix, or any diagnostic after the first;
 *   - other non-ASCII characters (other scripts, combining marks, U+FEFF,
 *     U+2028), Java `\uXXXX` escapes, or non-ASCII inside string literals
 *     (the surfaces' string literals are hex ByteStrings or tags);
 *   - on `.runar.ts`: `\uXXXX` escapes in identifiers (the source text is
 *     ASCII), template literals with `${}` substitutions, or which of several
 *     non-ASCII characters in one file a tier reports after the first;
 *   - ASCII control whitespace such as form feed or vertical tab;
 *   - columns after an earlier non-ASCII character on the same line (some
 *     tiers count bytes, TS counts UTF-16 units).
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n407-'));

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
  { ext: 'ts', path: 'examples/ts/arithmetic/Arithmetic.runar.ts', wsNeedle: 'a + b;', comment: '//', commentBefore: '    const diff' },
  { ext: 'sol', path: 'examples/sol/arithmetic/Arithmetic.runar.sol', wsNeedle: 'a + b;', comment: '//', commentBefore: '        int diff' },
  { ext: 'go', path: 'examples/go/arithmetic/Arithmetic.runar.go', wsNeedle: 'a + b\n', comment: '//', commentBefore: '\tdiff :=' },
  { ext: 'rs', path: 'examples/rust/arithmetic/Arithmetic.runar.rs', wsNeedle: 'a + b;', comment: '//', commentBefore: '        let diff' },
  { ext: 'py', path: 'examples/python/arithmetic/Arithmetic.runar.py', wsNeedle: 'a + b\n', comment: '#', commentBefore: '        diff:' },
  { ext: 'zig', path: 'examples/zig/arithmetic/Arithmetic.runar.zig', wsNeedle: 'a + b;', comment: '//', commentBefore: '        const diff' },
  { ext: 'rb', path: 'examples/ruby/arithmetic/Arithmetic.runar.rb', wsNeedle: 'a + b\n', comment: '#', commentBefore: '    diff =' },
  {
    ext: 'java',
    path: 'examples/java/src/main/java/runar/examples/arithmetic/Arithmetic.runar.java',
    wsNeedle: 'a.plus(b)',
    comment: '//',
    commentBefore: '        Bigint diff',
  },
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

describe('N-407 non-ASCII letters in identifiers and non-ASCII whitespace — every tier vs the TS reference', () => {
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
