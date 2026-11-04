/**
 * `@bindingVariant` directive parsing (ports #170; original design:
 * brendan-elas, #167).
 *
 * A public `.runar.ts` method may carry a `/** @bindingVariant <VARIANT> *\/`
 * comment directive selecting which Any-S OP_PUSH_TX preimage-binding
 * construction its `checkPreimage` (auto-injected or manual) emits:
 *
 *   - `lowS` (default): s = lowS((z + 1) mod n) against the C=1 key. Valid at
 *     every tx nVersion, including 1. Absent directive ⇒ this construction.
 *   - `all`: s = z + 1 as-is (no mod-n, no low-S), 46 bytes smaller. REJECTED
 *     at nVersion = 1 (LOW_S and minimal-number rules); ONLY spendable when the
 *     spending tx has nVersion != 1. The compiler cannot check that; the
 *     author owns it, and no Rúnar SDK builds such a transaction.
 *
 * Same marker rules as `@sighash` (F-039 / N-039): every occurrence of the
 * marker is a directive, more than one on a method is an error, and anything
 * other than ` lowS` / ` all` after it is an error — never a silent fall-back.
 * Like `@sighash` on `.runar.ts`, the detection lives in the parser; this
 * module owns the value grammar. The eight non-TS surfaces have no spelling
 * for it and refuse the marker (BINDING_VARIANT_UNSUPPORTED_MESSAGE).
 * Diagnostic text is identical in all seven tiers.
 */

import type { BindingVariant } from '../ir/anf-ir.js';

/** The construction a method uses when it carries no `@bindingVariant` directive. */
export const BINDING_VARIANT_DEFAULT: BindingVariant = 'lowS';

export const BINDING_VARIANT_MARKER = '@bindingVariant';

export const BINDING_VARIANT_MALFORMED_ERROR =
  '@bindingVariant: malformed directive; expected `@bindingVariant lowS` or `@bindingVariant all`';
export const BINDING_VARIANT_MULTIPLE_ERROR =
  '@bindingVariant: more than one @bindingVariant directive on this method; declare exactly one';

export type BindingVariantParseResult =
  | { value: BindingVariant }
  | { error: string };

/**
 * Parse the value after the marker. Case-sensitive: only `lowS` and `all`.
 */
export function parseBindingVariant(text: string): BindingVariantParseResult {
  const raw = text.trim();
  if (raw === 'lowS' || raw === 'all') return { value: raw };
  if (raw.length === 0) return { error: BINDING_VARIANT_MALFORMED_ERROR };
  return { error: `@bindingVariant: unknown variant "${raw}" (valid: lowS, all)` };
}

/**
 * Extract and parse a `@bindingVariant` directive from a method's
 * leading-comment text (all of its leading comments, concatenated). Returns
 * `null` only when no marker is present. The segment after the single marker,
 * up to `*` + `/`, a newline, CR or the end, must start with a space/tab and
 * hold only `[A-Za-z0-9_]`, spaces and tabs; anything else is malformed.
 */
export function extractBindingVariantDirective(commentText: string): BindingVariantParseResult | null {
  const first = commentText.indexOf(BINDING_VARIANT_MARKER);
  if (first === -1) return null;
  if (commentText.indexOf(BINDING_VARIANT_MARKER, first + 1) !== -1) {
    return { error: BINDING_VARIANT_MULTIPLE_ERROR };
  }
  const after = commentText.slice(first + BINDING_VARIANT_MARKER.length);
  let end = after.length;
  for (let i = 0; i < after.length; i++) {
    const c = after[i];
    if (c === '\n' || c === '\r' || (c === '*' && after[i + 1] === '/')) { end = i; break; }
  }
  const seg = after.slice(0, end);
  if (!/^[ \t][A-Za-z0-9_ \t]*$/.test(seg)) return { error: BINDING_VARIANT_MALFORMED_ERROR };
  return parseBindingVariant(seg);
}

/**
 * The non-TS surfaces' refusal, identical in all seven tiers. `surfaceName`
 * is the human-readable surface ("Solidity", "Go DSL", ...).
 */
export function bindingVariantUnsupportedMessage(surfaceName: string): string {
  return `@bindingVariant directive is not supported by the ${surfaceName} surface parser; write the contract in TypeScript (.runar.ts), where @bindingVariant is honoured`;
}
