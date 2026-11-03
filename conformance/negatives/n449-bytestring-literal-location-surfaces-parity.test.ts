import { describe, it, expect } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-449: the ByteString-literal hex diagnostics (odd length, non-hex
 * characters) carry the literal's `file:line:column` in every tier on the
 * eight non-`.runar.ts` surfaces. N-432 did this for `.runar.ts` only; on the
 * other surfaces the TS reference's hand-written parsers attached no location
 * to the literal, so every tier printed the message bare -- except Python,
 * whose validator fell back to the enclosing statement's location.
 *
 * Each case is the `hex-to-bytes-initializer` conformance fixture with ONE
 * literal replaced: either the first property initializer (`init()` body on
 * the Go and Rust surfaces, which have no inline initializer syntax) or a
 * literal added to the method body (`== script` becomes `== cat(script, X)`).
 *
 * The position is the literal's first character with the 0-based column of
 * N-078: the opening quote of a quoted literal, the `0` of a `0x...` literal.
 * When the surface spells the literal as a helper call (Go
 * `runar.HexToBytes("...")`, Zig `runar.hexToBytes("...")`, Python
 * `bytes.fromhex("...")`, Java `ByteString.fromHex("...")`, Rust
 * `to_byte_string("...")`) the position is the string literal INSIDE the
 * call. Every expected position is computed from the source text
 * (`lineText.indexOf(anchor)`), never copied from a compiler's output.
 *
 * What this proves: for every case below, all seven tiers refuse with the TS
 * message prefixed by `<file>:<line>:<col>:` at the literal (and so Python no
 * longer reports the statement's position instead).
 * What it does NOT prove:
 *   - non-hex on `.runar.sol` / `.runar.move` and on `0x...` literals: those
 *     tokens only consume hex digits, so the check is unreachable there;
 *     Python `b"..."` likewise always lowers to valid even-length hex;
 *   - literals inside array literals, asm() bodies or struct-literal fields;
 *   - that IR / hex do not move (the golden conformance run covers that).
 */

const TIERS = buildSourceTiers();
const DIR = mkdtempSync(join(tmpdir(), 'n449-literal-loc-'));
const FIXTURE = join(REPO, 'conformance/tests/hex-to-bytes-initializer');

const tsMessage = (lit: string): string =>
  lit.length % 2 !== 0
    ? `ByteString literal '${lit}' has odd length (${lit.length}) — hex strings must have an even number of characters`
    : `ByteString literal '${lit}' contains non-hex characters — only 0-9, a-f, A-F are allowed`;

interface Case {
  ext: string;
  where: 'prop' | 'method';
  lit: string;
  /** [text to replace in the fixture, replacement, anchor whose first char is the position]. */
  edit: (lit: string) => [string, string, string];
}

const ODD = 'abc';
const NON_HEX = 'zz';

const CASES: Case[] = [
  // Solidity-like and Move: 0x... is the only ByteString literal.
  { ext: 'sol', where: 'prop', lit: ODD, edit: (l) => ['0x1976a914', `0x${l}`, `0x${l}`] },
  { ext: 'sol', where: 'method', lit: ODD, edit: (l) => ['== script', `== cat(script, 0x${l})`, `0x${l}`] },
  { ext: 'move', where: 'prop', lit: ODD, edit: (l) => ['0x1976a914', `0x${l}`, `0x${l}`] },
  { ext: 'move', where: 'method', lit: ODD, edit: (l) => ['== script', `== cat(script, 0x${l})`, `0x${l}`] },
  // Go: runar.HexToBytes("...") (N-448), anchored at the inner literal.
  ...[ODD, NON_HEX].flatMap((lit): Case[] => [
    { ext: 'go', where: 'prop', lit, edit: (l) => ['"1976a914"', `"${l}"`, `"${l}"`] },
    { ext: 'go', where: 'method', lit, edit: (l) => ['== script', `== runar.Cat(script, runar.HexToBytes("${l}"))`, `"${l}"`] },
  ]),
  // Rust: to_byte_string("...") in init(), a bare string and 0x... in a method.
  ...[ODD, NON_HEX].flatMap((lit): Case[] => [
    { ext: 'rs', where: 'prop', lit, edit: (l) => ['"1976a914"', `"${l}"`, `"${l}"`] },
    { ext: 'rs', where: 'method', lit, edit: (l) => ['== script', `== cat(script, "${l}")`, `"${l}"`] },
  ]),
  { ext: 'rs', where: 'method', lit: ODD, edit: (l) => ['== script', `== cat(script, 0x${l})`, `0x${l}`] },
  // Python: bytes.fromhex("...") initializer, a bare string in a method.
  ...[ODD, NON_HEX].flatMap((lit): Case[] => [
    { ext: 'py', where: 'prop', lit, edit: (l) => ['"1976a914"', `"${l}"`, `"${l}"`] },
    { ext: 'py', where: 'method', lit, edit: (l) => ['== script', `== cat(script, "${l}")`, `"${l}"`] },
  ]),
  // Zig: runar.hexToBytes("...") (N-448), anchored at the inner literal.
  ...[ODD, NON_HEX].flatMap((lit): Case[] => [
    { ext: 'zig', where: 'prop', lit, edit: (l) => ['"1976a914"', `"${l}"`, `"${l}"`] },
    { ext: 'zig', where: 'method', lit, edit: (l) => ['), script)', `), runar.cat(script, runar.hexToBytes("${l}")))`, `"${l}"`] },
  ]),
  // Ruby: a single-quoted default, a double-quoted string in a method.
  ...[ODD, NON_HEX].flatMap((lit): Case[] => [
    { ext: 'rb', where: 'prop', lit, edit: (l) => ["'1976a914'", `'${l}'`, `'${l}'`] },
    { ext: 'rb', where: 'method', lit, edit: (l) => ['== script', `== cat(script, "${l}")`, `"${l}"`] },
  ]),
  // Java: ByteString.fromHex("...") in both positions.
  ...[ODD, NON_HEX].flatMap((lit): Case[] => [
    { ext: 'java', where: 'prop', lit, edit: (l) => ['"1976a914"', `"${l}"`, `"${l}"`] },
    { ext: 'java', where: 'method', lit, edit: (l) => ['.equals(script)', `.equals(cat(script, ByteString.fromHex("${l}")))`, `"${l}"`] },
  ]),
];

/** `<line>:<0-based column>` of `anchor`'s first character in `text`. */
function expectedPosition(text: string, anchor: string): string {
  const lines = text.split('\n');
  const idx = lines.findIndex((l) => l.includes(anchor));
  if (idx < 0) throw new Error(`anchor ${anchor} not in source`);
  return `${idx + 1}:${lines[idx]!.indexOf(anchor)}`;
}

/** The `L:C` a tier printed in front of `message` for `fileName`, or null. */
function printedPosition(diag: string, fileName: string, message: string): string | null {
  const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = diag.match(new RegExp(`${esc(fileName)}:(\\d+):(\\d+): ${esc(message)}`));
  return m ? `${m[1]}:${m[2]}` : null;
}

describe('N-449: ByteString-literal hex diagnostics carry the literal position on every surface', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  CASES.forEach(({ ext, where, lit, edit }, i) => {
    const [from, to, anchor] = edit(lit);
    it(`.runar.${ext} ${where} ${JSON.stringify(to)}: every tier prints :<line>:<col> of ${anchor}`, () => {
      const original = readFileSync(join(FIXTURE, `HexToBytesInitializer.runar.${ext}`), 'utf8');
      expect(original.split(from).length - 1, `${from} must occur once in the .${ext} fixture`).toBe(1);
      const text = original.replace(from, to);
      const fileName = `HexToBytesInitializer.runar.${ext}`;
      const sub = join(DIR, `case${i}`);
      const file = join(sub, fileName);
      mkdirSync(sub, { recursive: true });
      writeFileSync(file, text);
      const want = expectedPosition(text, anchor);
      const message = tsMessage(lit);
      const got: Record<string, string | null> = {};
      for (const tier of TIERS) {
        const r = judge(tier, file);
        expect(r.verdict, `${tier.id} must refuse ${fileName}`).toBe('rejected');
        expect(r.diag, `${tier.id} must print the TS message`).toContain(message);
        got[tier.id] = printedPosition(r.diag, fileName, message);
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, want])));
    }, 900_000);
  });
});
