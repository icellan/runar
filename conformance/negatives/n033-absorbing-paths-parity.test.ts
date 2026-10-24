import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex, REPO, type Tier } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-033 — the remaining silent absorbing paths on the .runar.py class body and
 * the .runar.zig field / parameter / struct-init lists, seven-tier parity.
 *
 * F-026 made .zig call and array lists require commas and refused a second
 * .py statement on a line. Three more loose paths were left (base matrix:
 * remediation-logs/N-033/matrix-base.txt):
 *   - every tier's .py class-body loop skipped a token it did not recognise,
 *     and a property-less identifier line (`bogus`, `bogus = 1`) was dropped
 *     with no diagnostic — all seven compiled such a class;
 *   - six .py tokenizers (all but TS) dropped a character they did not know,
 *     so a stray `;` vanished;
 *   - every tier's .zig field, parameter and struct-init loops took the
 *     separating `,` as optional, so `sig: runar.Sig pubKey: runar.PubKey`
 *     and `.{ .pubKeyHash = pubKeyHash limit = limit }` compiled.
 *
 * Every tier now refuses each shape with the TS reference's diagnostic at the
 * offending token (line 1-based, column 0-based):
 *   .py class body  `Unexpected token in class body: '<tok>'` (N-004's text);
 *   .py lexer       `Unexpected character '<c>'`;
 *   .zig lists      `expected ',' between list elements` (F-026's text). Zig
 *                   lets only the last field before `}` omit the comma, and
 *                   allows a trailing comma in all three lists.
 * The dotted struct-init shape (`pubKeyHash .limit = limit`) reads as the
 * member access `pubKeyHash.limit` in every tier, as it does in Zig, so the
 * missing comma is reported at the `=` that follows it.
 *
 * What this proves:
 *   - every available tier refuses each REFUSED shape and prints the shared
 *     diagnostic at the same line:column;
 *   - every tier refuses an over-indented class-body line (wording not pinned);
 *   - every tier compiles a .py `!` negation to the same hex (the Zig tier's
 *     .py tokenizer used to skip `!`, which silently dropped the negation);
 *   - every tier still compiles the unmodified P2PKH, a class-level `pass`,
 *     trailing commas in .zig params and struct-init, and a last .zig field
 *     with no comma before `}`, to the basic-p2pkh golden in both fold modes.
 * What it does NOT prove:
 *   - tokens after the .py class (still ignored; N-004 fixed that only for
 *     .rb), the optional leading `.` of a .zig struct-init field, or the
 *     .zig struct body's own skip of unknown tokens;
 *   - stray characters other than `;` on .py (the lexer change covers every
 *     character TS refuses, but only `;` is pinned here);
 *   - the diagnostics after the first one.
 */

const GOLDEN = readFileSync(join(REPO, 'conformance/tests/basic-p2pkh/expected-script.hex'), 'utf8').trim();
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));
const TMP = mkdtempSync(join(tmpdir(), 'n033-'));

const PY = readFileSync(join(REPO, 'examples/python/p2pkh/P2PKH.runar.py'), 'utf8');
const ZIG = readFileSync(join(REPO, 'examples/zig/p2pkh/P2PKH.runar.zig'), 'utf8');

function sub(text: string, from: string, to: string): string {
  if (!text.includes(from)) throw new Error(`template needle ${JSON.stringify(from)} not found`);
  return text.replace(from, to);
}

/** A second field `limit`, assigned by `init`, so a field list has two entries. */
const ZIG2 = sub(
  sub(
    sub(ZIG, '    pubKeyHash: runar.Addr,\n', '    pubKeyHash: runar.Addr,\n    limit: i64,\n'),
    'pub fn init(pubKeyHash: runar.Addr) P2PKH',
    'pub fn init(pubKeyHash: runar.Addr, limit: i64) P2PKH',
  ),
  'return .{ .pubKeyHash = pubKeyHash }',
  'return .{ .pubKeyHash = pubKeyHash, .limit = limit }',
);

const PY_LINE = '    pub_key_hash: Addr\n';
const pyWith = (line: string) => sub(PY, PY_LINE, `${PY_LINE}    ${line}\n`);

const BODY = (tok: string) => `Unexpected token in class body: '${tok}'`;
const COMMA = "expected ',' between list elements";

interface Refused {
  name: string;
  file: string;
  text: string;
  /** The offending token is the first occurrence of `mark` in `text`, at `off`. */
  mark: string;
  off: number;
  diag: string;
}

const REFUSED: Refused[] = [
  { name: 'a stray identifier line in a .py class body', file: 'P2PKH.runar.py',
    text: pyWith('bogus'), mark: '    bogus', off: 4, diag: BODY('bogus') },
  { name: 'a stray assignment line in a .py class body', file: 'P2PKH.runar.py',
    text: pyWith('bogus = 1'), mark: '    bogus', off: 4, diag: BODY('bogus') },
  { name: 'a stray number in a .py class body', file: 'P2PKH.runar.py',
    text: pyWith('42'), mark: '    42', off: 4, diag: BODY('42') },
  { name: 'a stray `;` in a .py class body', file: 'P2PKH.runar.py',
    text: pyWith(';'), mark: '    ;', off: 4, diag: "Unexpected character ';'" },
  { name: 'a missing comma between .zig fields', file: 'P2PKH.runar.zig',
    text: sub(ZIG2, '    pubKeyHash: runar.Addr,\n', '    pubKeyHash: runar.Addr\n'),
    mark: '    limit: i64', off: 4, diag: COMMA },
  { name: 'a missing comma after the last .zig field before a method', file: 'P2PKH.runar.zig',
    text: sub(ZIG, '    pubKeyHash: runar.Addr,\n', '    pubKeyHash: runar.Addr\n'),
    mark: '    pub fn init', off: 4, diag: COMMA },
  { name: 'a missing comma between .zig method params', file: 'P2PKH.runar.zig',
    text: sub(ZIG, 'sig: runar.Sig, pubKey', 'sig: runar.Sig pubKey'),
    mark: 'pubKey: runar.PubKey)', off: 0, diag: COMMA },
  { name: 'a missing comma between .zig init params', file: 'P2PKH.runar.zig',
    text: sub(ZIG2, 'pubKeyHash: runar.Addr, limit: i64) P2PKH', 'pubKeyHash: runar.Addr limit: i64) P2PKH'),
    mark: 'limit: i64) P2PKH', off: 0, diag: COMMA },
  { name: 'a missing comma in a .zig struct-init (bare field)', file: 'P2PKH.runar.zig',
    text: sub(ZIG2, '.pubKeyHash = pubKeyHash, .limit', '.pubKeyHash = pubKeyHash limit'),
    mark: 'limit = limit', off: 0, diag: COMMA },
  { name: 'a missing comma in a .zig struct-init (dotted field)', file: 'P2PKH.runar.zig',
    text: sub(ZIG2, '.pubKeyHash = pubKeyHash, .limit', '.pubKeyHash = pubKeyHash .limit'),
    mark: '.limit = limit', off: 7, diag: COMMA },
];

const REJECTED: Array<[string, string, string]> = [
  ['an over-indented .py class-body line', 'P2PKH.runar.py', pyWith('    other: Addr')],
];

const ACCEPTED: Array<[string, string, string]> = [
  ['the unmodified .py P2PKH', 'P2PKH.runar.py', PY],
  ['a .py class-level `pass`', 'P2PKH.runar.py', pyWith('pass')],
  ['the unmodified .zig P2PKH', 'P2PKH.runar.zig', ZIG],
  ['trailing commas in .zig params and struct-init', 'P2PKH.runar.zig',
    sub(sub(ZIG, 'pubKey: runar.PubKey) void', 'pubKey: runar.PubKey,) void'), '.pubKeyHash = pubKeyHash }', '.pubKeyHash = pubKeyHash, }')],
  ['a last .zig field with no comma before `}`', 'P2PKH.runar.zig',
    sub(sub(ZIG, '    pubKeyHash: runar.Addr,\n\n', ''), '    }\n};', '    }\n\n    pubKeyHash: runar.Addr\n};')],
];

let n = 0;
function write(file: string, text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, file);
  writeFileSync(p, text);
  return p;
}

describe('N-033 .py class body and .zig list separators — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const c of REFUSED) {
    const at = c.text.indexOf(c.mark);
    if (at < 0) throw new Error(`${c.name}: mark ${JSON.stringify(c.mark)} not found`);
    const lines = c.text.slice(0, at + c.off).split('\n');
    const pos = `:${lines.length}:${lines[lines.length - 1]!.length}: `;
    const path = write(c.file, c.text);
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic at ${pos.slice(1, -2)}`, () => {
        const j = judge(tier, path);
        expect(j.verdict, j.diag).toBe('rejected');
        expect(j.diag).toContain(`${pos}${c.diag}`);
      });
    }
  }

  for (const [name, file, text] of REJECTED) {
    const path = write(file, text);
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${name}`, () => {
        const j = judge(tier, path);
        expect(j.verdict, j.diag).toBe('rejected');
      });
    }
  }

  // The Zig tier's .py tokenizer had no `!` token and skipped the character,
  // so `!(a == b)` compiled as `(a == b)`. It now tokenizes `!` as TS does;
  // every tier must compile the negation to the same bytes.
  const bangPath = write('P2PKH.runar.py', sub(PY, 'assert_(hash160(pub_key) == self.pub_key_hash)', 'assert_(!(hash160(pub_key) != self.pub_key_hash))'));
  it('every tier compiles a .py `!` negation to the same hex', () => {
    const hexes = TIERS.map((t) => compileHex(t, bangPath));
    for (const h of hexes) expect(h).toBe(hexes[0]);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const [name, file, text] of ACCEPTED) {
      const path = write(file, text);
      for (const tier of tiers) {
        it(`${tier.id} (${mode}) compiles ${name} to the basic-p2pkh golden`, () => {
          expect(compileHex(tier, path)).toBe(GOLDEN);
        });
      }
    }
  }
});
