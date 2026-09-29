/**
 * `@sighash` directive parsing (issue #123).
 *
 * A public method may carry a `/** @sighash <FLAGS> *\/` comment directive that
 * declares which BIP-143 sighash type its auto-injected covenant (and the
 * SDK-built preimage) commits to. `<FLAGS>` is a `|`-separated set of SigHash
 * names, e.g. `SINGLE|FORKID`, `ALL|ANYONECANPAY|FORKID`, `NONE|FORKID`.
 *
 * The default (no directive) is `ALL|FORKID` (0x41) — byte-identical to the
 * historically-pinned mode, so existing fixtures see ZERO change.
 *
 * Reuses the exact two-surface directive shape #109 established for
 * `@embedAlways` (JSDoc block + leading trivia); the *detection* lives in the
 * parser, this module owns the *flag grammar* (name → value, combo validity).
 */

/** Numeric value of each sighash flag name. */
const FLAG_VALUES: Record<string, number> = {
  ALL: 0x01,
  NONE: 0x02,
  SINGLE: 0x03,
  FORKID: 0x40,
  ANYONECANPAY: 0x80,
};

/** The base-type names. Exactly one MUST appear in a directive. */
const BASE_TYPE_NAMES = new Set(['ALL', 'NONE', 'SINGLE']);

/** SIGHASH_ALL | SIGHASH_FORKID — the default when no directive is present. */
export const SIGHASH_DEFAULT = 0x41;

/**
 * Base-type mask. `sigHashType & BASE_TYPE_MASK` recovers 1/2/3 (ALL/NONE/
 * SINGLE) after the FORKID/ANYONECANPAY high bits are stripped.
 */
export const BASE_TYPE_MASK = 0x1f;
export const BASE_ALL = 0x01;
export const BASE_NONE = 0x02;
export const BASE_SINGLE = 0x03;
export const FLAG_FORKID = 0x40;
export const FLAG_ANYONECANPAY = 0x80;

export type SighashParseResult =
  | { value: number }
  | { error: string };

/**
 * Parse the flag list of an `@sighash` directive.
 *
 * `flagsText` is the raw text following `@sighash` (e.g. `"SINGLE|FORKID"`),
 * with any trailing comment punctuation already stripped by the caller.
 *
 * Validation (security-relevant — a mis-declared mode is an exploit class):
 *   - every name must be a known flag (reject typos like `FORKD`)
 *   - EXACTLY ONE base type (ALL/NONE/SINGLE) — reject zero, and reject
 *     nonsensical combos such as `ALL|NONE`. This is checked on NAMES, not on
 *     the OR-ed numeric value, because `ALL|NONE` (0x01|0x02) collides with the
 *     numeric value of SINGLE (0x03) — a silent, dangerous aliasing that a
 *     purely numeric check would miss.
 *   - reject a duplicated flag name (signals a copy/paste error).
 */
export function parseSighashFlags(flagsText: string): SighashParseResult {
  const raw = flagsText.trim();
  if (raw.length === 0) {
    return { error: '@sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)' };
  }

  const names = raw.split('|').map((n) => n.trim());
  const seen = new Set<string>();
  const baseTypes: string[] = [];
  let value = 0;

  for (const name of names) {
    if (name.length === 0) {
      return { error: `@sighash directive has an empty flag in "${raw}"` };
    }
    if (!(name in FLAG_VALUES)) {
      return {
        error: `@sighash: unknown flag "${name}" (valid: ALL, NONE, SINGLE, FORKID, ANYONECANPAY)`,
      };
    }
    if (seen.has(name)) {
      return { error: `@sighash: duplicate flag "${name}" in "${raw}"` };
    }
    seen.add(name);
    if (BASE_TYPE_NAMES.has(name)) baseTypes.push(name);
    value |= FLAG_VALUES[name]!;
  }

  if (baseTypes.length === 0) {
    return {
      error: `@sighash: must specify exactly one base type (ALL, NONE, or SINGLE); got "${raw}"`,
    };
  }
  if (baseTypes.length > 1) {
    return {
      error: `@sighash: cannot combine base types (${baseTypes.join('|')}) — pick exactly one of ALL/NONE/SINGLE`,
    };
  }

  // FORKID is mandatory on BSV: the entire OP_PUSH_TX / BIP-143 preimage
  // machinery is FORKID-only, so a FORKID-less flag set deploys a covenant
  // whose derived signature can never verify (deploy-to-brick). Reject it up
  // front rather than let a spendable-looking script ship.
  if ((value & FLAG_VALUES.FORKID!) === 0) {
    return {
      error: `@sighash: FORKID is mandatory on BSV; write e.g. @sighash ${baseTypes[0]}|FORKID (got "${raw}")`,
    };
  }

  return { value };
}

/**
 * Shared diagnostics (F-039). Identical text in all seven tiers: a marker that
 * is present but not followed by a well-formed flag list, or a second marker on
 * the same method, is a compile error — never a silent fall-back to the
 * default ALL|FORKID mode.
 */
export const SIGHASH_MALFORMED_ERROR =
  '@sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a |-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)';
export const SIGHASH_MULTIPLE_ERROR =
  '@sighash: more than one @sighash directive on this method; declare exactly one';

const SIGHASH_MARKER = '@sighash';

/** ASCII word character — the reference `\b` boundary (no `u` flag). */
function isWordChar(c: string): boolean {
  return /[A-Za-z0-9_]/.test(c);
}

/**
 * Extract and parse an `@sighash` directive from a method's leading-comment
 * text (all of its leading comments, concatenated). Returns `null` only when
 * no `@sighash` marker is present, otherwise the parse result (value or error).
 *
 * A marker is `@sighash` followed by a word boundary, so `@sighashType` (or
 * `@sighashSINGLE`) is prose, not a directive. Once a marker is present
 * (fail-closed, F-039):
 *   - more than one marker is an error (SIGHASH_MULTIPLE_ERROR);
 *   - the segment after the marker, up to `*` + `/`, a newline, CR or the end,
 *     must be empty, or start with a space/tab and contain only
 *     `[A-Za-z0-9_|]`, spaces and tabs — anything else is SIGHASH_MALFORMED_ERROR;
 *   - the flag list itself is then validated by `parseSighashFlags`.
 */
export function extractSighashDirective(commentText: string): SighashParseResult | null {
  const markers: number[] = [];
  for (let i = commentText.indexOf(SIGHASH_MARKER); i !== -1; i = commentText.indexOf(SIGHASH_MARKER, i + 1)) {
    const next = commentText[i + SIGHASH_MARKER.length];
    if (next === undefined || !isWordChar(next)) markers.push(i);
  }
  if (markers.length === 0) return null;
  if (markers.length > 1) return { error: SIGHASH_MULTIPLE_ERROR };

  const after = commentText.slice(markers[0]! + SIGHASH_MARKER.length);
  let end = after.length;
  for (let i = 0; i < after.length; i++) {
    const c = after[i];
    if (c === '\n' || c === '\r' || (c === '*' && after[i + 1] === '/')) { end = i; break; }
  }
  const seg = after.slice(0, end);
  if (seg.length > 0 && !/^[ \t][A-Za-z0-9_| \t]*$/.test(seg)) {
    return { error: SIGHASH_MALFORMED_ERROR };
  }
  return parseSighashFlags(seg);
}

/** Human-readable rendering of a sighash value (for diagnostics). */
export function describeSighash(value: number): string {
  const parts: string[] = [];
  const base = value & BASE_TYPE_MASK;
  if (base === BASE_ALL) parts.push('ALL');
  else if (base === BASE_NONE) parts.push('NONE');
  else if (base === BASE_SINGLE) parts.push('SINGLE');
  else parts.push(`0x${base.toString(16)}`);
  if (value & FLAG_ANYONECANPAY) parts.push('ANYONECANPAY');
  if (value & FLAG_FORKID) parts.push('FORKID');
  return parts.join('|');
}
