/**
 * `@bindingVariant` directive parsing.
 *
 * A public method may carry a `/** @bindingVariant <VARIANT> *\/` comment
 * directive selecting which Any-S OP_PUSH_TX preimage-binding construction its
 * auto-injected covenant emits:
 *
 *   - `lowS` (default): the canonical low-S construction (s = z + 2^248, low-S
 *     fixup, verified against the 2^248 key). Byte-identical to the historically
 *     -pinned blob — a method without the directive sees ZERO change. Accepted
 *     under the LOW_S rule that applies to spends with nVersion = 0x01000000, so
 *     it is safe under all tx versions.
 *   - `all`: the compact non-low-S construction (s = z + 1, no low-S fixup,
 *     verified against the C=1 key) — ~52 bytes smaller per binding. The derived
 *     signature can be high-S, so it is REJECTED under the LOW_S rule; it is ONLY
 *     valid for covenants whose spends use nVersion != 0x01000000, where LOW_S is
 *     not enforced. The author is responsible for that guarantee — the compiler
 *     cannot verify a spend-time property.
 *
 * Reuses the exact two-surface directive shape #123 established for `@sighash`
 * (JSDoc block + leading trivia): the *detection* lives in the parser, this
 * module owns the *value grammar*. Like `@sighash`, it is a TypeScript-surface
 * directive — the eight non-TS surface parsers fail closed on it.
 */

import type { BindingVariant } from './oppushtx-codegen.js';

/** The construction a method uses when it carries no `@bindingVariant` directive. */
export const BINDING_VARIANT_DEFAULT: BindingVariant = 'lowS';

/** Recognised variant names (as written in the directive), mapped to their value. */
const VARIANT_VALUES: Record<string, BindingVariant> = {
  lowS: 'lowS',
  all: 'all',
};

export type BindingVariantParseResult =
  | { variant: BindingVariant }
  | { error: string };

/**
 * Parse the value of a `@bindingVariant` directive.
 *
 * `variantText` is the raw text following `@bindingVariant` (e.g. `"all"`), with
 * any trailing comment punctuation already stripped by the caller. The match is
 * case-sensitive: `all` and `lowS` are the only accepted spellings, so a typo
 * (`All`, `low_s`, `high`) is rejected rather than silently defaulted — a
 * mis-declared binding is an exploit class (a covenant that ships `all` while its
 * spends use nVersion = 1 is unspendable; the inverse ships needless bytes).
 */
export function parseBindingVariant(variantText: string): BindingVariantParseResult {
  const raw = variantText.trim();
  if (raw.length === 0) {
    return { error: '@bindingVariant directive requires a value (`@bindingVariant all` or `@bindingVariant lowS`)' };
  }
  const variant = VARIANT_VALUES[raw];
  if (variant === undefined) {
    return { error: `@bindingVariant: unknown variant "${raw}" (valid: lowS, all)` };
  }
  return { variant };
}

/**
 * Extract and parse a `@bindingVariant` directive from a block of comment text.
 * Returns `null` when no `@bindingVariant` token is present, otherwise the parse
 * result (variant or error). Used by the parser after it has collected a
 * method's JSDoc / leading-comment trivia.
 */
const BINDING_VARIANT_RE = /@bindingVariant\s+([A-Za-z0-9_]*?)(?:\*\/|\n|\r|\s|$)/;
export function extractBindingVariantDirective(commentText: string): BindingVariantParseResult | null {
  const m = BINDING_VARIANT_RE.exec(commentText);
  if (!m) return null;
  return parseBindingVariant(m[1] ?? '');
}
