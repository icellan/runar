import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex, REPO, type Tier } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-410 — the last silent absorbing paths on the .runar.py and .runar.zig
 * surfaces, seven-tier parity. N-033 closed the .py class-body and .zig list
 * shapes and listed these three as still open:
 *   - every tier's .py parser stopped at the class's last DEDENT and ignored
 *     whatever followed it (N-004 closed that for .runar.rb only), so a
 *     `def drain` / second class / stray token after the class compiled;
 *   - every tier's .zig struct-body loop skipped a token that is not a
 *     `pub const Contract`, a method or a `name:` field (`42`, `;`, `=`, a
 *     stray `pub`), so a line of the struct vanished with no diagnostic;
 *   - every tier's .zig struct-init loop took the leading `.` of a field as
 *     optional, so `return .{ pubKeyHash = pubKeyHash }` compiled. Zig's
 *     grammar is `FieldInit <- DOT IDENTIFIER EQUAL Expr` (the dot is
 *     required; docs/formats/zig.md writes every struct-init with it).
 *
 * Every tier now refuses each shape at the offending token (line 1-based,
 * column 0-based) with one shared diagnostic:
 *   .py after the class   `Unexpected token after class end: '<tok>'` (N-004's text);
 *   .zig struct body      `Unexpected token in struct body: '<tok>'`;
 *   .zig struct-init      `expected '.' before struct-init field name`.
 *
 * What this proves:
 *   - every available tier refuses each REFUSED shape and prints the shared
 *     diagnostic at the same line:column;
 *   - every tier refuses a bare identifier line in a .zig struct body (wording
 *     and position not pinned);
 *   - every tier still compiles the unmodified .py / .zig P2PKH, a .py class
 *     followed only by blank lines and comments, and a two-field .zig
 *     struct-init with dots, to the basic-p2pkh golden in both fold modes.
 * What it does NOT prove:
 *   - tokens after the closing `};` of a .zig struct, or a second .py class
 *     other than through the `class` token's text;
 *   - the diagnostics after the first one, or token text for string tokens;
 *   - that a .zig struct body without any stray token is otherwise valid.
 */

const GOLDEN = readFileSync(join(REPO, 'conformance/tests/basic-p2pkh/expected-script.hex'), 'utf8').trim();
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));
const TMP = mkdtempSync(join(tmpdir(), 'n410-'));

const PY = readFileSync(join(REPO, 'examples/python/p2pkh/P2PKH.runar.py'), 'utf8');
const ZIG = readFileSync(join(REPO, 'examples/zig/p2pkh/P2PKH.runar.zig'), 'utf8');

function sub(text: string, from: string, to: string): string {
  if (!text.includes(from)) throw new Error(`template needle ${JSON.stringify(from)} not found`);
  return text.replace(from, to);
}

/** A second field `limit`, assigned by `init`, so a struct-init has two entries. */
const ZIG2 = sub(
  sub(
    sub(ZIG, '    pubKeyHash: runar.Addr,\n', '    pubKeyHash: runar.Addr,\n    limit: i64,\n'),
    'pub fn init(pubKeyHash: runar.Addr) P2PKH',
    'pub fn init(pubKeyHash: runar.Addr, limit: i64) P2PKH',
  ),
  'return .{ .pubKeyHash = pubKeyHash }',
  'return .{ .pubKeyHash = pubKeyHash, .limit = limit }',
);

const ZIG_FIELD = '    pubKeyHash: runar.Addr,\n';
const zigWith = (line: string) => sub(ZIG, ZIG_FIELD, `${ZIG_FIELD}    ${line}\n`);

const AFTER = (tok: string) => `Unexpected token after class end: '${tok}'`;
const STRUCT = (tok: string) => `Unexpected token in struct body: '${tok}'`;
const DOT = "expected '.' before struct-init field name";

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
  { name: 'a stray identifier line after the .py class', file: 'P2PKH.runar.py',
    text: `${PY}\nbogus\n`, mark: '\nbogus', off: 1, diag: AFTER('bogus') },
  { name: 'a stray number after the .py class', file: 'P2PKH.runar.py',
    text: `${PY}\n42\n`, mark: '\n42', off: 1, diag: AFTER('42') },
  { name: 'a method defined after the .py class', file: 'P2PKH.runar.py',
    text: `${PY}\ndef drain(sig):\n    pass\n`, mark: '\ndef drain', off: 1, diag: AFTER('def') },
  { name: 'a second class after the .py class', file: 'P2PKH.runar.py',
    text: `${PY}\nclass Other(SmartContract):\n    pass\n`, mark: '\nclass Other', off: 1, diag: AFTER('class') },
  { name: 'a stray number in a .zig struct body', file: 'P2PKH.runar.zig',
    text: zigWith('42'), mark: '    42', off: 4, diag: STRUCT('42') },
  { name: 'a stray `;` in a .zig struct body', file: 'P2PKH.runar.zig',
    text: zigWith(';'), mark: '    ;', off: 4, diag: STRUCT(';') },
  { name: 'a stray `=` in a .zig struct body', file: 'P2PKH.runar.zig',
    text: zigWith('= 1'), mark: '    = 1', off: 4, diag: STRUCT('=') },
  { name: 'a stray `pub` before a .zig struct field', file: 'P2PKH.runar.zig',
    text: zigWith('pub limit: i64,'), mark: '    pub limit', off: 4, diag: STRUCT('pub') },
  { name: 'a first .zig struct-init field without its leading `.`', file: 'P2PKH.runar.zig',
    text: sub(ZIG, '.pubKeyHash = pubKeyHash }', 'pubKeyHash = pubKeyHash }'),
    mark: 'pubKeyHash = pubKeyHash }', off: 0, diag: DOT },
  { name: 'a later .zig struct-init field without its leading `.`', file: 'P2PKH.runar.zig',
    text: sub(ZIG2, '.pubKeyHash = pubKeyHash, .limit', '.pubKeyHash = pubKeyHash, limit'),
    mark: 'limit = limit', off: 0, diag: DOT },
];

// A bare identifier line in a .zig struct body is no field (no `:`). TS refuses
// it through its generic `expect(':')`; the other tiers' generic wording and
// position differ, so only the refusal is pinned.
const REJECTED: Array<[string, string, string]> = [
  ['a stray identifier line in a .zig struct body', 'P2PKH.runar.zig', zigWith('bogus,')],
];

const ACCEPTED: Array<[string, string, string]> = [
  ['the unmodified .py P2PKH', 'P2PKH.runar.py', PY],
  ['blank lines and a comment after the .py class', 'P2PKH.runar.py', `${PY}\n\n# trailing note\n\n`],
  ['the unmodified .zig P2PKH', 'P2PKH.runar.zig', ZIG],
  ['a .zig line comment inside the struct body', 'P2PKH.runar.zig', zigWith('// a note')],
];

// Two struct-init entries, both dotted, compile to a different contract (an
// extra `limit` field), so this control compares tiers with each other
// instead of with the golden.
const ZIG2_PATH_NAME = 'a two-field .zig struct-init with leading dots';

let n = 0;
function write(file: string, text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, file);
  writeFileSync(p, text);
  return p;
}

describe('N-410 .py code after the class and .zig struct body / struct-init — seven-tier parity', () => {
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

  const zig2Path = write('P2PKH.runar.zig', ZIG2);
  it(`every tier compiles ${ZIG2_PATH_NAME} to the same hex`, () => {
    const hexes = TIERS.map((t) => compileHex(t, zig2Path));
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
