import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { parse } from '../passes/01-parse.js';
import { invalidEscapeSequenceMessage, PY_BYTES_NON_ASCII } from '../errors.js';

/**
 * F-203 (CL-BUG-208..213) — .runar.py byte literals decode escapes the way
 * CPython bytes literals do.
 *
 * Before the fix the tiers disagreed with CPython and with each other: the
 * Python tier decoded `\0` to one byte while TS and Go hex-encoded the two
 * characters `\` `0`; every tier hex-encoded `b'\n'`, `b'\t'`, `b'\\'`
 * character by character, so a `len(tag) == 1` check passed under pytest
 * (CPython) and failed on-chain. TS also ended `b'\''` at the escaped quote.
 *
 * The rule (user decision R59), defined here and ported to all seven tiers:
 *   - b'..' / b".." decode `\\ \' \" \a \b \f \n \r \t \v`, octal `\NNN`
 *     (1-3 digits, value at most 0o377) and `\xHH` (exactly two hex digits);
 *   - any other escape — one CPython does not define for bytes (`\q`, `\N`,
 *     `\u`, `\U`), a short or non-hex `\x`, an octal escape above 0o377 — is
 *     refused with `invalid escape sequence '<escape>'` (CPython warns and keeps
 *     the backslash, or raises; we fail closed);
 *   - a non-ASCII character in a bytes literal is refused with CPython's
 *     `bytes can only contain ASCII literal characters`;
 *   - plain '..' / ".." strings (hex text) decode the same escapes, so the hex
 *     validator sees what CPython would; `\u`, `\U`, `\N{..}` are refused there
 *     too (the surface does not support them);
 *   - a backslash-newline continuation stays refused as an unterminated literal
 *     (the surface has no multi-line single-quoted literals), and prefixes
 *     other than a lone lowercase `b` (rb, br, B, r, u, f) are refused.
 *
 * Every expected byte string below is CPython's own: `python3 -c "print(b'..'.hex())"`.
 *
 * What this proves: the reference tier compiles each escape to CPython's bytes
 * and refuses each undefined or unsupported form.
 * What it does NOT prove: the other six tiers (their own suites and
 * conformance/negatives/py-bytes-escape-parity.test.ts cover that).
 */

const FILE = 'Esc.runar.py';

/** A contract whose only guard is `x == <literal>`. */
const contract = (lit: string): string => `from runar import SmartContract, ByteString, public, assert_


class Esc(SmartContract):
    def __init__(self):
        super().__init__()

    @public
    def unlock(self, x: ByteString):
        assert_(x == ${lit})
`;

/** Minimal push of `hex` as the emitter encodes byte strings, then OP_EQUAL. */
function guardHex(hex: string): string {
  const n = hex.length / 2;
  let push: string;
  if (n === 0) push = '00';
  else if (n === 1 && parseInt(hex, 16) >= 1 && parseInt(hex, 16) <= 16) push = (0x50 + parseInt(hex, 16)).toString(16);
  else if (n === 1 && hex === '81') push = '4f';
  else if (n <= 75) push = n.toString(16).padStart(2, '0') + hex;
  else throw new Error('test helper handles short literals only');
  return push + '87';
}

/** [Python source body between b'..', CPython's b'..'.hex()]. */
const BYTES_CASES: Array<[string, string]> = [
  ['\\0', '00'],
  ['\\00', '00'],
  ['\\000', '00'],
  ['\\7', '07'],
  ['\\101', '41'],
  ['\\377', 'ff'],
  ['\\1234', '5334'],
  ['a\\0b', '610062'],
  ['\\08', '0038'],
  ['\\n', '0a'],
  ['\\t', '09'],
  ['\\r', '0d'],
  ['\\\\', '5c'],
  ["\\'", '27'],
  ['\\"', '22'],
  ['\\a', '07'],
  ['\\b', '08'],
  ['\\f', '0c'],
  ['\\v', '0b'],
  ['\\xde\\xAD', 'dead'],
  ['\\x00\\x6a', '006a'],
  ['ab', '6162'],
  ['\\\\n', '5c6e'],
  ['x\\ty\\nz', '7809790a7a'],
];

function errors(src: string): string[] {
  return parse(src, FILE).errors.map((e) => e.message);
}

describe('F-203 the shared diagnostics', () => {
  it('have fixed text', () => {
    expect(invalidEscapeSequenceMessage('\\q')).toBe("invalid escape sequence '\\q'");
    expect(PY_BYTES_NON_ASCII).toBe('bytes can only contain ASCII literal characters');
  });
});

describe("F-203 b'..' escapes decode to CPython's bytes", () => {
  for (const [body, hex] of BYTES_CASES) {
    it(`b'${body}' -> ${hex}`, () => {
      const r = compile(contract(`b'${body}'`), { fileName: FILE });
      expect(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message)).toEqual([]);
      expect(r.scriptHex).toBe(guardHex(hex));
    });
  }

  it(`b"\\'\\"" -> 2722 (both escaped quotes inside double quotes)`, () => {
    const r = compile(contract(`b"\\'\\""`), { fileName: FILE });
    expect(r.scriptHex).toBe(guardHex('2722'));
  });

  it('a plain hex-text string decodes CPython escapes before the hex check: "\\x61\\x62" is "ab"', () => {
    const r = compile(contract('"\\x61\\x62"'), { fileName: FILE });
    expect(r.scriptHex).toBe(guardHex('ab'));
  });
});

describe('F-203 refusals', () => {
  const INVALID: Array<[string, string]> = [
    ["b'\\q'", '\\q'],
    ["b'\\x4'", '\\x'],
    ["b'\\xg0'", '\\x'],
    ["b'\\400'", '\\400'],
    ["b'\\N{DIGIT ONE}'", '\\N'],
    ["b'\\u0041'", '\\u'],
    ["b'\\U00000041'", '\\U'],
    ['"\\q"', '\\q'],
    ['"\\u0061"', '\\u'],
  ];
  for (const [lit, esc] of INVALID) {
    it(`${lit} is refused with invalid escape sequence '${esc}'`, () => {
      expect(errors(contract(lit))).toContain(invalidEscapeSequenceMessage(esc));
      expect(compile(contract(lit), { fileName: FILE }).success).toBe(false);
    });
  }

  it("a non-ASCII character in b'..' is refused", () => {
    expect(errors(contract("b'é'"))).toContain(PY_BYTES_NON_ASCII);
  });

  for (const lit of ["rb'\\n'", "br'\\n'", "B'\\n'", "r'ab'", "u'ab'", "f'ab'"]) {
    it(`prefix form ${lit} is refused`, () => {
      expect(compile(contract(lit), { fileName: FILE }).success).toBe(false);
    });
  }

  it('a backslash-newline continuation inside b\'..\' is refused (unterminated)', () => {
    expect(compile(contract("b'ab\\\ncd'"), { fileName: FILE }).success).toBe(false);
  });
});
