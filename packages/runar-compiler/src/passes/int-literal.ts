/**
 * F-026 — integer literals mean what their host language says they mean.
 *
 * User decision R15: every surface accepts exactly the integer-literal forms
 * its host language defines, with that language's value, and refuses every
 * form the language rejects with one shared diagnostic. All seven tiers
 * implement this table; this file is the reference.
 *
 * Tokenizing rule, all hand-written tokenizers on all surfaces: a number
 * token starts at a decimal digit and runs over every following
 * `[0-9A-Za-z_]` character. A letter glued to a number can therefore never
 * become a separate identifier token. That is how `0b1010` used to compile to
 * `0` on `.runar.zig` / `.runar.py`: the decimal scanner stopped at `b`, the
 * stray identifier `b1010` was absorbed, and a threshold guard became `> 0`.
 *
 * `0x` (lowercase) on `.runar.sol`, `.runar.move` and `.runar.rs` is NOT an
 * integer: those surfaces spell ByteString literals that way (`0x1976a914`),
 * so their tokenizers handle it before a number is scanned. On every other
 * surface `0x` is a hexadecimal integer, as in the host language.
 *
 * Per-surface forms (host-language references in the doc of each matcher):
 *
 *   ts    0 | [1-9](_?d)*, 0b/0B 0o/0O 0x/0X with digit(_?digit)*, each with an
 *         optional BigInt suffix `n`. Legacy octal and leading zeros (`012`,
 *         `08`, `00`) are refused: TS files are strict-mode modules.
 *   sol   0 | [1-9](_?d)*. No octal, binary or leading zeros.
 *   move  [0-9][0-9_]* with an optional u8..u256 suffix; the value must fit
 *         the suffix type (u256 when unsuffixed).
 *   go    0 | [1-9](_?d)*, legacy octal 0(_?[0-7])+, 0o/0O 0x/0X 0b/0B with
 *         (_?digit)+ (a `_` may follow the prefix).
 *   rs    decimal / 0o / 0b (lowercase prefixes) with `_` anywhere after the
 *         first character and at least one digit, optional i8..i128, isize,
 *         u8..u128, usize suffix; suffixed values must fit the type
 *         (the signed minimum only under a unary minus). Unsuffixed values
 *         are unbounded: rustc stops at u128::MAX, but Rúnar's corpus writes
 *         256-bit constants this way (examples/rust/schnorr-zkp).
 *   py    [1-9](_?d)* | 0(_?0)*, 0b/0B 0o/0O 0x/0X with (_?digit)+.
 *   zig   0 | [1-9](_?d)*, 0x 0o 0b (lowercase) with digit(_?digit)*.
 *   rb    0 | [1-9](_?d)*, 0d/0D, legacy octal 0_?[0-7](_?[0-7])*, 0o/0O,
 *         0x/0X, 0b/0B with digit(_?digit)*.
 *   java  JLS 3.10.1: decimal, octal (leading 0), 0x/0X, 0b/0B, `_` between
 *         digits (repeatable), optional L/l. An int literal must fit 32 bits
 *         and a long 64 bits; hex / octal / binary values wrap to two's
 *         complement (`0xFFFFFFFF` is -1), and the decimal `2147483648` /
 *         `9223372036854775808L` are valid only under a unary minus.
 *
 * Values are exact integers at arbitrary precision. Where the host language
 * would narrow or round a value by TYPE (JavaScript `Number`, Rust inferred
 * `i64`, Go/Zig/Solidity constant conversion), Rúnar keeps the exact value;
 * only the literal-level limits above are enforced.
 */

export type LiteralSurface = 'ts' | 'sol' | 'move' | 'go' | 'rs' | 'py' | 'zig' | 'rb' | 'java';

export const SURFACE_LANGUAGE: Record<LiteralSurface, string> = {
  ts: 'TypeScript',
  sol: 'Solidity',
  move: 'Move',
  go: 'Go',
  rs: 'Rust',
  py: 'Python',
  zig: 'Zig',
  rb: 'Ruby',
  java: 'Java',
};

/**
 * The one refusal every tier emits for a malformed integer literal. It names
 * the surface's language and quotes the literal exactly as written.
 */
export function invalidIntegerLiteral(surface: LiteralSurface, text: string): string {
  return `invalid ${SURFACE_LANGUAGE[surface]} integer literal '${text}'`;
}

export interface IntLiteral {
  value: bigint;
  /**
   * The literal is valid only as the direct operand of a unary minus: Java's
   * `2147483648` / `9223372036854775808L` and a Rust signed-suffix minimum
   * such as `128i8`. `value` is the positive magnitude.
   */
  negOnly: boolean;
}

/** A character that continues a number token. */
export function isNumberContinue(ch: string | undefined): boolean {
  return ch !== undefined && /^[0-9A-Za-z_]$/.test(ch);
}

/** End (exclusive) of the number token whose first digit is at `pos`. */
export function scanNumberEnd(source: string, pos: number): number {
  let i = pos + 1;
  while (i < source.length && isNumberContinue(source[i])) i++;
  return i;
}

function digitsValue(digits: string, radix: number): bigint {
  const r = BigInt(radix);
  let v = 0n;
  for (const ch of digits) {
    if (ch === '_') continue;
    v = v * r + BigInt(parseInt(ch, 16));
  }
  return v;
}

function ok(value: bigint, negOnly = false): IntLiteral {
  return { value, negOnly };
}

const RADIX: Record<string, number> = { x: 16, X: 16, o: 8, O: 8, b: 2, B: 2, d: 10, D: 10 };

/** `0<p>digits` with the digits captured in group 1. */
function prefixed(text: string, re: RegExp): IntLiteral | null {
  const m = re.exec(text);
  if (!m) return null;
  return ok(digitsValue(m[1]!, RADIX[text[1]!]!));
}

// ECMA-262 (ES2022) 12.9.3 NumericLiteral / BigIntLiteralSuffix; legacy octal
// and NonOctalDecimalIntegerLiteral are early errors in strict mode code.
function parseTs(text: string): IntLiteral | null {
  const body = text.endsWith('n') ? text.slice(0, -1) : text;
  if (/^(?:0|[1-9](?:_?[0-9])*)$/.test(body)) return ok(digitsValue(body, 10));
  return (
    prefixed(body, /^0[xX]([0-9a-fA-F](?:_?[0-9a-fA-F])*)$/) ??
    prefixed(body, /^0[oO]([0-7](?:_?[0-7])*)$/) ??
    prefixed(body, /^0[bB]([01](?:_?[01])*)$/)
  );
}

// Solidity docs, "Rational and Integer Literals": decimal digits, `_` only
// between two digits, no octal, leading zeros invalid.
function parseSol(text: string): IntLiteral | null {
  return /^(?:0|[1-9](?:_?[0-9])*)$/.test(text) ? ok(digitsValue(text, 10)) : null;
}

const MOVE_BITS: Record<string, number> = { u8: 8, u16: 16, u32: 32, u64: 64, u128: 128, u256: 256 };

// The Move Book, "Integers": digits with `_` separators and an optional
// integer-type suffix whose range bounds the value; unsuffixed literals are
// bounded by u256.
function parseMove(text: string): IntLiteral | null {
  const m = /^([0-9][0-9_]*)(u8|u16|u32|u64|u128|u256)?$/.exec(text);
  if (!m) return null;
  const v = digitsValue(m[1]!, 10);
  const bits = MOVE_BITS[m[2] ?? 'u256']!;
  return v < 1n << BigInt(bits) ? ok(v) : null;
}

// The Go Programming Language Specification, "Integer literals".
function parseGo(text: string): IntLiteral | null {
  if (/^(?:0|[1-9](?:_?[0-9])*)$/.test(text)) return ok(digitsValue(text, 10));
  const legacy = /^0((?:_?[0-7])+)$/.exec(text);
  if (legacy) return ok(digitsValue(legacy[1]!, 8));
  return (
    prefixed(text, /^0[xX]((?:_?[0-9a-fA-F])+)$/) ??
    prefixed(text, /^0[oO]((?:_?[0-7])+)$/) ??
    prefixed(text, /^0[bB]((?:_?[01])+)$/)
  );
}

const RUST_BITS: Record<string, [number, boolean]> = {
  i8: [8, true], i16: [16, true], i32: [32, true], i64: [64, true], i128: [128, true], isize: [64, true],
  u8: [8, false], u16: [16, false], u32: [32, false], u64: [64, false], u128: [128, false], usize: [64, false],
};

// The Rust Reference, "Integer literals" (+ the deny-by-default
// `overflowing_literals` lint for suffixed literals; `isize`/`usize` are
// taken as 64-bit). rustc also refuses an unsuffixed literal above
// u128::MAX; Rúnar does not, because its Int is a bigint and the corpus
// spells the secp256k1 group order that way.
function parseRust(text: string): IntLiteral | null {
  const m = /^(?:0x([0-9a-fA-F_]*)|0o([0-7_]*)|0b([01_]*)|([0-9][0-9_]*))(i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize)?$/.exec(text);
  if (!m) return null;
  const [digits, radix] =
    m[1] !== undefined ? [m[1], 16] : m[2] !== undefined ? [m[2], 8] : m[3] !== undefined ? [m[3], 2] : [m[4]!, 10];
  if (!/[0-9a-fA-F]/.test(digits)) return null;
  const v = digitsValue(digits, radix);
  const suffix = m[5];
  if (suffix === undefined) return ok(v);
  const [bits, signed] = RUST_BITS[suffix]!;
  if (!signed) return v < 1n << BigInt(bits) ? ok(v) : null;
  const min = 1n << BigInt(bits - 1);
  if (v < min) return ok(v);
  return v === min ? ok(v, true) : null;
}

// The Python Language Reference, 2.4.5 "Integer literals".
function parsePy(text: string): IntLiteral | null {
  if (/^(?:[1-9](?:_?[0-9])*|0(?:_?0)*)$/.test(text)) return ok(digitsValue(text, 10));
  return (
    prefixed(text, /^0[xX]((?:_?[0-9a-fA-F])+)$/) ??
    prefixed(text, /^0[oO]((?:_?[0-7])+)$/) ??
    prefixed(text, /^0[bB]((?:_?[01])+)$/)
  );
}

// The Zig Language Reference, "Integer Literals" (std.zig.number_literal):
// lowercase prefixes, `_` only between digits, no leading zeros.
function parseZig(text: string): IntLiteral | null {
  if (/^(?:0|[1-9](?:_?[0-9])*)$/.test(text)) return ok(digitsValue(text, 10));
  return (
    prefixed(text, /^0x([0-9a-fA-F](?:_?[0-9a-fA-F])*)$/) ??
    prefixed(text, /^0o([0-7](?:_?[0-7])*)$/) ??
    prefixed(text, /^0b([01](?:_?[01])*)$/)
  );
}

// Ruby documentation, "Literals" -> "Integer Literals" (doc/syntax/literals.rdoc).
function parseRb(text: string): IntLiteral | null {
  if (/^(?:0|[1-9](?:_?[0-9])*)$/.test(text)) return ok(digitsValue(text, 10));
  const legacy = /^0(_?[0-7](?:_?[0-7])*)$/.exec(text);
  if (legacy) return ok(digitsValue(legacy[1]!, 8));
  return (
    prefixed(text, /^0[dD]([0-9](?:_?[0-9])*)$/) ??
    prefixed(text, /^0[xX]([0-9a-fA-F](?:_?[0-9a-fA-F])*)$/) ??
    prefixed(text, /^0[oO]([0-7](?:_?[0-7])*)$/) ??
    prefixed(text, /^0[bB]([01](?:_?[01])*)$/)
  );
}

// The Java Language Specification (SE 17), 3.10.1 "Integer Literals".
function parseJava(text: string): IntLiteral | null {
  const isLong = /[lL]$/.test(text);
  const body = isLong ? text.slice(0, -1) : text;
  const bits = isLong ? 64n : 32n;
  if (/^(?:0|[1-9](?:[0-9_]*[0-9])?)$/.test(body)) {
    const v = digitsValue(body, 10);
    const min = 1n << (bits - 1n);
    if (v < min) return ok(v);
    return v === min ? ok(v, true) : null;
  }
  let v: bigint | null = null;
  const oct = /^0([0-7_]*[0-7])$/.exec(body);
  if (oct) v = digitsValue(oct[1]!, 8);
  const hex = /^0[xX]([0-9a-fA-F](?:[0-9a-fA-F_]*[0-9a-fA-F])?)$/.exec(body);
  if (hex) v = digitsValue(hex[1]!, 16);
  const bin = /^0[bB]([01](?:[01_]*[01])?)$/.exec(body);
  if (bin) v = digitsValue(bin[1]!, 2);
  if (v === null || v >= 1n << bits) return null;
  return ok(v >= 1n << (bits - 1n) ? v - (1n << bits) : v);
}

/**
 * The value of the integer literal `text` (the whole number token) on
 * `surface`, or null when the host language rejects it.
 */
export function parseIntLiteral(surface: LiteralSurface, text: string): IntLiteral | null {
  switch (surface) {
    case 'ts': return parseTs(text);
    case 'sol': return parseSol(text);
    case 'move': return parseMove(text);
    case 'go': return parseGo(text);
    case 'rs': return parseRust(text);
    case 'py': return parsePy(text);
    case 'zig': return parseZig(text);
    case 'rb': return parseRb(text);
    case 'java': return parseJava(text);
  }
}
