import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * N-274 — `docs/testing-guide.md`'s "Testing Rust Contracts" section
 * (~:1220) has a "Mock crypto" table row claiming the native Rust prelude's
 * `check_sig`, `check_multi_sig`, `check_preimage`, `verify_rabin_sig`, and
 * `verify_wots` all "always return `true`". That directly contradicts the
 * SAME document's cross-tier comparison table (~:656), which says:
 *
 *   | Rust | **real** (`check_sig`) | `mock_sig()`, `mock_pub_key()`, `mock_preimage()` |
 *
 * Ground truth (`packages/runar-rs/src/prelude.rs`):
 *   check_sig         REAL ECDSA verify over the fixed TEST_MESSAGE (:115-117)
 *   check_multi_sig   REAL ordered multi-sig ECDSA verify (:123-133)
 *   check_preimage    stubbed to the literal `true` (:136-138) — this ONE
 *                     claim in the old row was actually correct
 *   verify_rabin_sig  REAL Rabin verification (:144-146)
 *   verify_wots       REAL WOTS+ verification (:149-151)
 *
 * This test pins the corrected claims in the "Testing Rust Contracts"
 * section only. It does NOT touch the "Cryptographic verification in tests"
 * cross-tier table (~:653-660), the interpreter table (~:666-677), or the
 * TypeScript-interpreter mock-crypto claims (~:207-208, :565, :649) — those
 * describe a different component (the TS AST interpreter, not the native
 * Rust prelude) and are F-298's scope, not N-274's.
 *
 * It also pins the section's "Basic Test Structure" example (~:1120-1134),
 * which used to call `c.unlock(&mock_sig(), &pk)` against a P2PKH contract
 * whose `unlock` runs the now-correctly-documented REAL `check_sig`.
 * `mock_sig()` / `mock_pub_key()` (`prelude.rs`:1283-1293) are all-zero dummy
 * bytes, not a valid signature/key pair, so that example would not actually
 * pass if copy-pasted — it predates this fix but is now a direct
 * contradiction of the corrected claim sitting right above it. The example
 * is rewritten to the `ALICE` / `BOB` test-identity pattern the shipped
 * `examples/rust/p2pkh/P2PKH_test.rs` already uses.
 */

const REPO = resolve(__dirname, '../../../..');
const DOC_PATH = resolve(REPO, 'docs/testing-guide.md');
const PRELUDE_PATH = resolve(REPO, 'packages/runar-rs/src/prelude.rs');

/** Functions whose native Rust prelude implementation is real, not mocked. */
const REAL_FNS = ['check_sig', 'check_multi_sig', 'verify_rabin_sig', 'verify_wots'];
/** The one function the prelude genuinely stubs to a literal `true`. */
const MOCKED_FN = 'check_preimage';

const MOCK_CLAIM = '(?:always\\s+returns?\\s+`?true`?|\\balways\\s+`?true`?)';

/** Slice out the "## Testing Rust Contracts" section (up to the next `## ` heading). */
function rustContractsSection(doc: string): string {
  const lines = doc.split('\n');
  const startIdx = lines.findIndex((l) => l.trim() === '## Testing Rust Contracts');
  if (startIdx === -1) {
    throw new Error('docs/testing-guide.md: "## Testing Rust Contracts" heading not found');
  }
  let endIdx = lines.findIndex((l, i) => i > startIdx && /^## /.test(l));
  if (endIdx === -1) endIdx = lines.length;
  return lines.slice(startIdx, endIdx).join('\n');
}

/**
 * True if `prelude` defines `pub fn <name>(...)` whose entire body is the
 * trivial stub `{ true }` (matches `check_preimage`'s real shape). Real
 * implementations call out to `crate::ecdsa` / `crate::rabin` / `crate::wots`
 * and never reduce to this pattern.
 */
function isTrivialTrueStub(prelude: string, name: string): boolean {
  const re = new RegExp('pub fn ' + name + '\\([^)]*\\)\\s*(?:->\\s*bool\\s*)?\\{\\s*true\\s*\\}');
  return re.test(prelude);
}

/** Extract the first ```rust fenced code block following a heading within `section`. */
function fencedRustBlockAfter(section: string, heading: string): string {
  const idx = section.indexOf(heading);
  if (idx === -1) {
    throw new Error(`"${heading}" not found in the "Testing Rust Contracts" section`);
  }
  const rest = section.slice(idx);
  const fenceStart = rest.indexOf('```rust');
  if (fenceStart === -1) {
    throw new Error(`no \`\`\`rust fence found after "${heading}"`);
  }
  const bodyStart = rest.indexOf('\n', fenceStart) + 1;
  const fenceEnd = rest.indexOf('```', bodyStart);
  if (fenceEnd === -1) {
    throw new Error(`unterminated \`\`\`rust fence after "${heading}"`);
  }
  return rest.slice(bodyStart, fenceEnd);
}

describe('N-274: docs/testing-guide.md "Testing Rust Contracts" matches the runar-rs prelude', () => {
  const doc = readFileSync(DOC_PATH, 'utf8');
  const section = rustContractsSection(doc);
  const prelude = readFileSync(PRELUDE_PATH, 'utf8');

  for (const name of REAL_FNS) {
    it(`doc: does not claim \`${name}\` always returns true / is mocked`, () => {
      const re = new RegExp('`' + name + '`[^\\n]{0,160}?' + MOCK_CLAIM, 'i');
      const hit = re.exec(section);
      expect(
        hit,
        `"Testing Rust Contracts" still claims \`${name}\` always returns true: ${JSON.stringify(hit?.[0])}`
      ).toBeNull();
    });

    it(`prelude.rs: \`${name}\` is a real implementation, not a literal \`true\` stub`, () => {
      expect(
        isTrivialTrueStub(prelude, name),
        `prelude.rs's \`${name}\` looks like a trivial \`{ true }\` stub, contradicting the test's premise`
      ).toBe(false);
    });
  }

  it(`doc: still documents \`${MOCKED_FN}\` as always returning true (the one claim that was already correct)`, () => {
    const re = new RegExp('`' + MOCKED_FN + '`[^\\n]{0,160}?' + MOCK_CLAIM, 'i');
    expect(
      re.test(section),
      `"Testing Rust Contracts" no longer documents \`${MOCKED_FN}\` as always-true`
    ).toBe(true);
  });

  it(`prelude.rs: \`${MOCKED_FN}\` is still the trivial \`{ true }\` stub`, () => {
    expect(isTrivialTrueStub(prelude, MOCKED_FN)).toBe(true);
  });

  it('doc: the cross-tier comparison table still documents Rust check_sig as real (guards against "fixing" the wrong row)', () => {
    expect(doc).toMatch(/\|\s*Rust\s*\|\s*\*\*real\*\*\s*\(`check_sig`\)/);
  });

  describe('"Basic Test Structure" example (~:1120-1134)', () => {
    const example = fencedRustBlockAfter(section, '### Basic Test Structure');

    it('does not unlock a real-check_sig P2PKH with mock_sig()/mock_pub_key()', () => {
      expect(
        example,
        'the example still calls mock_sig()/mock_pub_key() against unlock(), which runs the now-documented-real check_sig — those are all-zero dummy bytes (prelude.rs mock_sig/mock_pub_key) and would not actually verify'
      ).not.toMatch(/mock_sig\(\)|mock_pub_key\(\)/);
    });

    it('uses the ALICE/BOB real-signature test-identity pattern that examples/rust/p2pkh/P2PKH_test.rs ships', () => {
      expect(example).toMatch(/ALICE\.pub_key/);
      expect(example).toMatch(/ALICE\.sign_test_message\(\)/);
      expect(example).toMatch(/BOB\.pub_key/);
      expect(example).toMatch(/BOB\.sign_test_message\(\)/);
    });

    it('prelude.rs: ALICE and BOB are real exported test identities (re-exported from test_keys)', () => {
      expect(prelude).toMatch(/pub use crate::test_keys::\{[^}]*\bALICE\b[^}]*\bBOB\b[^}]*\}/);
    });
  });
});
