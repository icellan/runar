/**
 * CK21-FU2 (checkpoint-21 red): N-093 (da1fb3dee) added two conformance
 * fixtures — compiler-directives and embed-always-fixed-array — to
 * conformance/tests/ without adding either an sdk-output mirror
 * (conformance/sdk-output/tests/<name>/) or an approved-omission entry in
 * conformance/sdk-output/coverage-allowlist.json. sdk-runner's own coverage
 * audit (`sdk-runner.ts --audit`, and the audit `main()` runs inline before
 * the suite) therefore exits 1 before running a single SDK:
 *
 *   [FAIL] 2 compiler-conformance fixture(s) absent from sdk-output and NOT approved:
 *     - compiler-directives
 *     - embed-always-fixed-array
 *
 * This test calls the audit in-process (rather than only ever exercising it
 * via the CLI's `--audit` subprocess path) so a future fixture that
 * regresses this gate is caught by `npx vitest run` alongside the rest of
 * the suite.
 */
import { describe, it, expect } from 'vitest';
import { runCoverageAudit } from './sdk-runner.js';

describe('CK21-FU2: sdk-output coverage audit', () => {
  it('exits 0 — every compiler-conformance fixture is mirrored under sdk-output/tests/ or approved in coverage-allowlist.json', () => {
    // What this proves: the audit that gates every CI run of sdk-runner.ts
    // (and which CI runs directly via `npx tsx .../sdk-runner.ts`) currently
    // reports clean coverage — no compiler-conformance fixture is silently
    // unmirrored and un-approved. Before this item's fix it returned 1,
    // naming compiler-directives and embed-always-fixed-array.
    // What this does NOT prove: that the two new sdk-output fixtures'
    // expected-locking.hex are byte-correct, that all 7 SDKs agree on them,
    // or that their golden-provenance-allowlist.json entries are valid — see
    // the full `sdk-runner.ts` run and `check-golden-provenance.mjs` for
    // those.
    expect(runCoverageAudit()).toBe(0);
  });
});
