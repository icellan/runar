import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * F-203 — .runar.py byte-literal escapes decode the way CPython does, in every
 * tier.
 *
 * Before the fix the same .runar.py source compiled to different bytes per
 * tier and differently from CPython (which is what pytest runs): the Python
 * tier decoded `\0` to 00 while TS and Go emitted 5c 30, and every tier
 * hex-encoded `b'\n'`, `b'\t'`, `b'\\'` character by character, so a
 * `len(tag) == 1` check passed under pytest and failed on-chain.
 *
 * The rule (user decision R59, reference: packages/runar-compiler/src/__tests__/
 * f203-py-bytes-escapes.test.ts):
 *   - b'..' / b".." decode `\\ \' \" \a \b \f \n \r \t \v`, octal `\NNN`
 *     (1-3 digits, at most 0o377) and `\xHH` (exactly two hex digits);
 *   - any other escape is refused with `invalid escape sequence '<escape>'`;
 *     a non-ASCII character in b'..' with
 *     `bytes can only contain ASCII literal characters`;
 *   - plain '..' strings (hex text) decode the same escapes before the hex
 *     check, and refuse `\u` / `\U` / `\N`;
 *   - backslash-newline continuations and rb / br / B prefixes stay refused.
 *
 * How the expectation is derived: every escaped literal's bytes come from
 * CPython (`python3 -c "print(b'..'.hex())"`), and the reference program
 * spells those same bytes with `\xHH` only. Every tier must compile the
 * escaped program to the bytes the TS reference compiles the `\xHH` program
 * to, in both fold modes.
 *
 * What this proves: all available tiers decode each escape to CPython's bytes
 * (byte-identical scripts), and refuse each undefined or unsupported form with
 * the shared diagnostic.
 * What it does NOT prove: escapes in literal kinds the surface does not scan
 * (triple-quoted docstrings are skipped, never compiled), or anything on the
 * other eight surfaces.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));
const TS = TIERS.find((t) => t.id === 'ts');

/** [escaped literal as written in .runar.py, CPython's bytes as hex]. */
const CASES: Array<[string, string]> = [
  ["b'\\0'", '00'],
  ["b'\\00'", '00'],
  ["b'\\000'", '00'],
  ["b'\\7'", '07'],
  ["b'\\101'", '41'],
  ["b'\\377'", 'ff'],
  ["b'\\1234'", '5334'],
  ["b'a\\0b'", '610062'],
  ["b'\\08'", '0038'],
  ["b'\\n'", '0a'],
  ["b'\\t'", '09'],
  ["b'\\r'", '0d'],
  ["b'\\\\'", '5c'],
  ["b'\\''", '27'],
  ["b'\\\"'", '22'],
  ["b\"\\'\\\"\"", '2722'],
  ["b'\\a'", '07'],
  ["b'\\b'", '08'],
  ["b'\\f'", '0c'],
  ["b'\\v'", '0b'],
  ["b'\\\\n'", '5c6e'],
  ["b'x\\ty\\nz'", '7809790a7a'],
  ["b'\\xde\\xAD'", 'dead'],
  ['"\\x61\\x62"', 'ab'],
];

const xhh = (hex: string): string => `b'${hex.replace(/../g, (b) => `\\x${b}`)}'`;

/** One public method; parameter i must equal literal i. */
const program = (lits: string[]): string => `from runar import SmartContract, ByteString, public, assert_


class Esc(SmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self, ${lits.map((_, i) => `x${i}: ByteString`).join(', ')}):
${lits.map((l, i) => `        assert_(x${i} == ${l})`).join('\n')}
`;

const single = (lit: string): string => program([lit]);

const INVALID = (esc: string): string => `invalid escape sequence '${esc}'`;
const NON_ASCII = 'bytes can only contain ASCII literal characters';

/** [case name, literal, diagnostic every tier must print (null: any refusal)]. */
const REFUSED: Array<[string, string, string | null]> = [
  ['unknown escape \\q', "b'\\q'", INVALID('\\q')],
  ['short \\x', "b'\\x4'", INVALID('\\x')],
  ['non-hex \\x', "b'\\xg0'", INVALID('\\x')],
  ['octal above 0o377', "b'\\400'", INVALID('\\400')],
  ['\\N{..} in bytes', "b'\\N{DIGIT ONE}'", INVALID('\\N')],
  ['\\u in bytes', "b'\\u0041'", INVALID('\\u')],
  ['\\U in bytes', "b'\\U00000041'", INVALID('\\U')],
  ['non-ASCII in bytes', "b'é'", NON_ASCII],
  ['unknown escape in a str', '"\\q"', INVALID('\\q')],
  ['\\u in a str', '"\\u0061"', INVALID('\\u')],
  ['rb prefix', "rb'\\n'", null],
  ['br prefix', "br'\\n'", null],
  ['B prefix', "B'\\n'", null],
  ['backslash-newline continuation', "b'ab\\\ncd'", null],
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'f203-py-bytes-escapes-'));
});

let seq = 0;
function write(src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'Esc.runar.py');
  writeFileSync(p, src);
  return p;
}

function refusal(tier: Tier, file: string): string {
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(file)], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${tier.id} could not run: ${r.error.message}`);
  if (r.status === 0) throw new Error(`${tier.id} ${file}: compiled (${r.stdout.trim().slice(-40)}), expected a refusal`);
  return `${r.stderr ?? ''}\n${r.stdout ?? ''}`;
}

describe('F-203 .runar.py byte-literal escapes — seven-tier parity with CPython', () => {
  it('at least two tiers are available, the TS reference among them (all seven in CI)', () => {
    expect(TS).toBeDefined();
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  // The same bytes, spelled with \xHH only: independent of escape decoding.
  const reference: Record<string, string> = {};
  beforeAll(() => {
    const ref = write(program(CASES.map(([, hex]) => xhh(hex))));
    const tsOff = FOLD_OFF_TIERS.find((t) => t.id === 'ts');
    if (TS && tsOff) {
      reference['fold-on'] = compileHex(TS, ref);
      reference['fold-off'] = compileHex(tsOff, ref);
    }
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const tier of tiers) {
      it(`${tier.id} (${mode}) compiles every escape to CPython's bytes`, () => {
        expect(reference[mode]).toBeTruthy();
        expect(compileHex(tier, write(program(CASES.map(([lit]) => lit))))).toBe(reference[mode]);
      });
    }
  }

  for (const [name, lit, diag] of REFUSED) {
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${name}`, () => {
        const out = refusal(tier, write(single(lit)));
        if (diag !== null) expect(out).toContain(diag);
      });
    }
  }
});
