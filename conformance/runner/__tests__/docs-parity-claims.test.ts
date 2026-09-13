/**
 * R-096 — the documented parity invariant must match what the runner enforces.
 *
 * Six documents claimed all seven tiers produce "byte-identical Stack IR and
 * byte-identical Bitcoin Script hex". The hex half is enforced. The Stack-IR
 * half was enforced by nothing: `CompilerOutput` (runner.ts) carries
 * `irJson` — canonical JSON of the **ANF** IR, which is pass 4, upstream of
 * stack lowering — plus `scriptHex` and `scriptAsm`, and the runner compares
 * the first two. Stack IR is never serialized by any tier and never compared.
 *
 * `scriptAsm` is not a stand-in for it either: the native tiers all return
 * `scriptAsm: ''` (runner.ts, the native compile path), so the field is live
 * for the TypeScript tier alone and is never diffed.
 *
 * Why this matters rather than being a wording nit: the peephole optimizer runs
 * ON Stack IR, between passes 5 and 6. A tier whose peephole differs is exactly
 * the case an unenforced Stack-IR claim would appear to cover and does not —
 * and the Zig tier is known to carry peephole rules its peers lack.
 *
 * Closing the gap for real means teaching seven CLIs to serialize Stack IR in
 * an agreed canonical form and diffing it — a new cross-tier wire format, which
 * is the same shape of change that produced the `syntheticArrayChain` split
 * (N-095). That is a deliberate piece of work, not a docs edit. Until it is
 * done, the documents say what is true.
 *
 * This test pins the corrected wording. It fails if the overclaim returns, and
 * it is satisfied EITHER by the docs being accurate or by a runner that really
 * does diff Stack IR — mirroring the finding's own acceptance criterion.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '../../..');

/**
 * Documents that state the project's parity invariant.
 *
 * `runar-verification/` carries the same sentence in two files and is
 * deliberately absent: it is a separate proof artifact with its own review
 * gate, out of scope for this repo's remediation.
 */
const DOCS = [
  'README.md',
  'CLAUDE.md',
  'spec/README.md',
  'docs/testing-guide.md',
  'packages/runar-go/README.md',
];

/** The overclaim, in the spellings the six documents used. */
const OVERCLAIM = /byte-identical\s+Stack[- ]IR\b|Stack[- ]IR\s+and\s+byte-identical/i;

/** True when some runner mode actually materialises and compares Stack IR. */
function runnerComparesStackIr(): boolean {
  const runner = readFileSync(join(REPO, 'conformance/runner/runner.ts'), 'utf-8');
  return /stackIr|stack_ir|stackIR/.test(runner);
}

describe('R-096: documented parity claims match the enforced ones', () => {
  it('the document set exists (an empty sweep would pass vacuously)', () => {
    const missing = DOCS.filter((d) => !existsSync(join(REPO, d)));
    expect(missing, `these documents are gone: ${missing.join(', ')}`).toEqual([]);
    expect(DOCS.length).toBeGreaterThanOrEqual(5);
  });

  for (const doc of DOCS) {
    it(`${doc} does not claim byte-identical Stack IR`, () => {
      const text = readFileSync(join(REPO, doc), 'utf-8');
      const hits = text
        .split('\n')
        .map((line, i) => ({ line, n: i + 1 }))
        .filter(({ line }) => OVERCLAIM.test(line));

      if (hits.length > 0 && runnerComparesStackIr()) return; // the other way to be right

      expect(
        hits.map((h) => `${doc}:${h.n}`),
        `${doc} claims byte-identical Stack IR, but the conformance runner ` +
          `compares canonical ANF IR and script hex only — Stack IR is never ` +
          `serialized by any tier. Either correct the sentence or add a runner ` +
          `mode that really diffs Stack IR.`,
      ).toEqual([]);
    });
  }
});

/**
 * R-130 — the same document's OTHER parity claim: which tiers carry the
 * EVM/STARK crypto families.
 *
 * CLAUDE.md said Baby Bear, KoalaBear, Poseidon2, BN254, Merkle, SP1 FRI and
 * FiatShamir-KB "ship Stack-IR codegen in the Go tier only". Measured: a
 * BabyBear contract compiles to the SAME bytes (9504010000789700…) in go,
 * rust, python, zig and ruby, only Java refuses, and TypeScript ships its own
 * `*-codegen.ts` for every one of those families WITH unit tests. A reviewer
 * taking the old wording at face value would classify a divergence in them as
 * out of scope — which is exactly what a governing document must not cause.
 *
 * The policy itself is real: those fixtures carry a `"compilers": ["go"]`
 * allowlist, so parity is not REQUIRED of the other tiers. This test pins the
 * distinction the corrected paragraph draws — conformance scope vs. where code
 * exists — by failing if the "Go tier only" phrasing comes back while the
 * other tiers' codegen is still there.
 */
describe('R-130: the Go-only claim matches where codegen actually lives', () => {
  const TS_CODEGEN = [
    'packages/runar-compiler/src/passes/babybear-codegen.ts',
    'packages/runar-compiler/src/passes/koalabear-codegen.ts',
    'packages/runar-compiler/src/passes/merkle-codegen.ts',
    'packages/runar-compiler/src/passes/bn254-codegen.ts',
  ];

  it('the TypeScript tier really does carry this codegen (else the claim would be fine)', () => {
    const missing = TS_CODEGEN.filter((f) => !existsSync(join(REPO, f)));
    expect(
      missing,
      `these are gone, so the "Go tier only" wording may be true again — ` +
        `re-check CLAUDE.md before deleting this test: ${missing.join(', ')}`,
    ).toEqual([]);
  });

  it('CLAUDE.md does not say those families ship in the Go tier only', () => {
    const text = readFileSync(join(REPO, 'CLAUDE.md'), 'utf-8');
    const hits = text
      .split('\n')
      .map((line, i) => ({ line, n: i + 1 }))
      // The corrected paragraph QUOTES the old sentence to explain what
      // changed, so only an assertion counts: the phrase used as a claim, not
      // inside the quotation that names it wrong.
      .filter(({ line }) => /ship Stack-IR codegen in the \*\*Go tier only\*\*/.test(line))
      .filter(({ line }) => !/used to say|factually wrong/.test(line));

    expect(
      hits.map((h) => `CLAUDE.md:${h.n}`),
      'CLAUDE.md claims these families ship in the Go tier only, but rust, ' +
        'python, zig, ruby and TypeScript all carry codegen for them and agree ' +
        'with Go byte for byte (conformance/go-only-parity). Say what the policy ' +
        'governs — the conformance allowlist — rather than where code exists.',
    ).toEqual([]);
  });
});
