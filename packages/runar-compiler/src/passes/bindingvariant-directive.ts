/**
 * `@bindingVariant` directive parsing.
 *
 * A public method may carry a `/** @bindingVariant <VARIANT> *\/` comment
 * directive selecting which Any-S OP_PUSH_TX preimage-binding construction its
 * auto-injected covenant emits:
 *
 *   - `lowS` (default): s = lowS((z + 1) mod n) against the C=1 key. Canonical
 *     s ≤ n/2, accepted under the LOW_S rule (nVersion = 1). Safe under all tx
 *     versions. Absent directive ⇒ this construction.
 *   - `all`: s = z + 1 as-is (no mod-n, no low-S) against the same C=1 key —
 *     ~45 bytes smaller. REJECTED under LOW_S; ONLY valid for spends with
 *     nVersion != 1. The author is responsible for that guarantee.
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
 *
 * Only a JSDoc/line-comment TAG at the start of a comment line is a directive.
 * Mid-sentence mentions (`Do NOT use @bindingVariant all`) and trailing junk
 * (`@bindingVariant: all`, `@bindingVariant all;`) are errors, not silent
 * default-to-lowS and not silent opt-in to `all`.
 */
const BINDING_VARIANT_TOKEN_RE = /@bindingVariant\b/;

function stripCommentLinePrefix(raw: string): string {
  return raw
    .replace(/^[ \t]+/, '')
    .replace(/^(?:\/\/|\/\*\*?|\*)[ \t]*/, '')
    .replace(/[ \t]*(?:\*\/)?[ \t]*$/, '');
}

export function extractBindingVariantDirective(commentText: string): BindingVariantParseResult | null {
  if (!BINDING_VARIANT_TOKEN_RE.test(commentText)) return null;
  for (const raw of commentText.split(/\r?\n/)) {
    const line = stripCommentLinePrefix(raw);
    if (!line.startsWith('@bindingVariant')) continue;
    const rest = line.slice('@bindingVariant'.length);
    if (rest.length > 0 && /[A-Za-z0-9_]/.test(rest[0]!)) continue;
    if (rest.length > 0 && rest[0] !== ' ' && rest[0] !== '\t') {
      return { error: '@bindingVariant must be a JSDoc tag at the start of a comment line (`@bindingVariant all` or `@bindingVariant lowS`)' };
    }
    return parseBindingVariant(rest.trim());
  }
  return {
    error: '@bindingVariant must be a JSDoc tag at the start of a comment line (`@bindingVariant all` or `@bindingVariant lowS`)',
  };
}
