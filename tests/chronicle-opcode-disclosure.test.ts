import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const ROOT = resolve(__dirname, '..');

/**
 * Rúnar emits Bitcoin Script for the **Chronicle** opcode policy, and no
 * user-facing document said so. `OP_2MUL` (0x8d) sits inside the 428-byte
 * `checkPreimage` binding blob that every stateful contract carries, and the
 * EC / NIST-P / Merkle primitives emit `OP_2DIV` (0x8e) and `OP_RSHIFTNUM`
 * (0xb7). A reader could go from the README to a funded mainnet output without
 * ever learning which node policy their coins depend on.
 *
 * Chronicle activated on BSV mainnet at block 943,816 on 7 April 2026 (SV Node
 * v1.2.0), so this is a *compatibility* disclosure, not a "do not deploy"
 * warning: consensus is fine, but any tool still on the pre-Chronicle policy
 * mis-handles these scripts. The Rust `bsv-sdk` is exactly such a tool, which is
 * why `docs/audit/upstream-bsv-sdk-op2mul-chronicle.md` exists.
 *
 * This suite is the gate. It fails if a user-facing entry point stops carrying
 * the disclosure, if the stated activation status drifts, or if the emitter
 * gains a Chronicle-gated codepoint the canonical reference does not name — so
 * the disclosure cannot silently fall behind the codegen.
 */

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/** The canonical long-form reference every other document points at. */
const REFERENCE_DOC = 'docs/chronicle-opcode-policy.md';

/**
 * Entry points a user actually reads before putting money on a contract. Each
 * must carry the disclosure itself, not merely a link to somewhere that has it.
 */
const ENTRY_POINT_DOCS = [
  'README.md',
  'docs/getting-started.md',
  'SECURITY.md',
  'docs/integration-guide.md',
  'docs/api-reference.md',
];

/**
 * Codepoints that only carry their Rúnar meaning under the Chronicle policy:
 * `OP_2MUL` / `OP_2DIV` (disabled pre-Chronicle) and 0xb3–0xb7 (`OP_NOP4`–
 * `OP_NOP8` pre-Chronicle).
 */
const CHRONICLE_BYTES = new Set([0x8d, 0x8e, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7]);

/**
 * The mainnet activation height. Requiring the height rather than a vague
 * phrase is deliberate: it is a single checkable fact, it cannot be satisfied by
 * a doc that merely name-drops "Chronicle", and if BSV ever reorganises this
 * history the gate goes red instead of quietly lying to readers.
 */
const MAINNET_ACTIVATION_HEIGHT = /943[,_]?816/;

/**
 * The Chronicle-gated opcode names the TypeScript emitter can actually produce,
 * read out of the emitter's own table rather than restated here. Adding a
 * Chronicle codepoint to `06-emit.ts` without documenting it turns this red.
 */
function chronicleOpcodeNames(): string[] {
  const src = readFileSync(resolve(ROOT, 'packages/runar-compiler/src/passes/06-emit.ts'), 'utf8');
  const start = src.indexOf('export const OPCODES');
  expect(start, 'OPCODES table not found in 06-emit.ts — update this gate').toBeGreaterThan(-1);
  const end = src.indexOf('\n};', start);
  expect(end, 'OPCODES table has no terminator — update this gate').toBeGreaterThan(start);

  const names: string[] = [];
  const entry = /'(OP_[A-Z0-9_]+)'\s*:\s*0x([0-9a-fA-F]{2})/g;
  let m: RegExpExecArray | null;
  while ((m = entry.exec(src.slice(start, end))) !== null) {
    const [, name, byte] = m;
    if (name === undefined || byte === undefined) continue;
    if (CHRONICLE_BYTES.has(parseInt(byte, 16))) names.push(name);
  }
  return names;
}

function read(rel: string): string {
  return readFileSync(resolve(ROOT, rel), 'utf8');
}

/**
 * True when `text` holds a window that mentions Chronicle, names `OP_2MUL`, and
 * states the activation status — all close enough together to be one disclosure
 * rather than three unrelated sentences scattered through an 800-line document.
 */
function hasDisclosureWindow(text: string, windowChars = 2500): boolean {
  const lower = text.toLowerCase();
  for (let i = lower.indexOf('chronicle'); i !== -1; i = lower.indexOf('chronicle', i + 1)) {
    const window = lower.slice(Math.max(0, i - windowChars), i + windowChars);
    if (!window.includes('op_2mul')) continue;
    if (!MAINNET_ACTIVATION_HEIGHT.test(window)) continue;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Chronicle opcode policy disclosure', () => {
  it('the emitter really does carry Chronicle-gated codepoints (gate liveness)', () => {
    // A gate that finds nothing to check reports green forever. If this list
    // ever empties, the disclosure requirement below is vacuous and the suite
    // must be revisited rather than deleted.
    const names = chronicleOpcodeNames();
    expect(names).toContain('OP_2MUL');
    expect(names).toContain('OP_RSHIFTNUM');
    expect(names.length).toBeGreaterThanOrEqual(5);
  });

  it.each(ENTRY_POINT_DOCS)('%s discloses the Chronicle dependency and its activation status', (rel) => {
    const text = read(rel);
    expect(
      /chronicle/i.test(text),
      `${rel} never mentions the Chronicle opcode policy that its own compiler output requires`,
    ).toBe(true);
    expect(
      hasDisclosureWindow(text),
      `${rel} mentions Chronicle but does not, in one place, name OP_2MUL and give the mainnet ` +
        `activation height. A passing mention is not a disclosure.`,
    ).toBe(true);
  });

  it('the canonical reference names every Chronicle-gated opcode the emitter can produce', () => {
    const doc = read(REFERENCE_DOC);
    for (const name of chronicleOpcodeNames()) {
      expect(doc, `${REFERENCE_DOC} does not name ${name}`).toContain(name);
    }
  });

  it('the canonical reference states BOTH pre-Chronicle failure modes', () => {
    const doc = read(REFERENCE_DOC);
    const lower = doc.toLowerCase();

    // Mode 1 — OP_2MUL / OP_2DIV are *disabled* pre-Chronicle: a clean abort.
    expect(lower, 'the disabled-opcode failure mode is not described').toContain('disabled opcode');

    // Mode 2 — 0xb3–0xb7 decode as upgradable NOPs pre-Chronicle. This is the
    // dangerous half: at the consensus layer they are no-ops, so a stale
    // validator computes a WRONG result instead of rejecting. If the reference
    // stops saying so, the most important sentence in it is gone.
    expect(lower, 'the OP_NOP decode of 0xb3-0xb7 is not described').toContain('op_nop8');
    expect(
      /no-?op|silent/.test(lower),
      'the reference does not say the NOP decode executes silently rather than aborting',
    ).toBe(true);
  });

  it('the canonical reference points at the evidence in this repo', () => {
    const doc = read(REFERENCE_DOC);
    // A reader who does not know the integration suite pins the policy on cannot
    // judge what a green integration run does and does not demonstrate.
    expect(doc).toContain('chronicleactivationheight');
    expect(doc).toContain('integration/regtest.sh');
    // The known pre-Chronicle tool in this repo's own dependency set.
    expect(doc).toContain('bsv-sdk');
  });

  it('every entry point routes the reader to the canonical reference', () => {
    for (const rel of ENTRY_POINT_DOCS) {
      expect(read(rel), `${rel} does not link ${REFERENCE_DOC}`).toContain('chronicle-opcode-policy.md');
    }
  });

  it('no document still describes Chronicle as unavailable', () => {
    // `docs/language-reference.md` carried "planned for the BSV 2026 CHRONICLE
    // upgrade but is not yet widely available" for OP_RSHIFTNUM. That was true
    // when written and became false on 2026-04-07. A disclosure that contradicts
    // another page of the same manual is not a disclosure.
    const stale = /not yet widely available|is planned for the BSV 2026 CHRONICLE upgrade/i;
    for (const rel of ['docs/language-reference.md', REFERENCE_DOC, ...ENTRY_POINT_DOCS]) {
      expect(stale.test(read(rel)), `${rel} still describes Chronicle as not yet available`).toBe(false);
    }
  });
});
