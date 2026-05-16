/**
 * Test-environment helpers shared by example/integration tests.
 *
 * `IS_CI` matches the convention used elsewhere in the repo
 * (e.g. `cross-compiler.test.ts`) and `runSlowTests` adds a local
 * opt-in flag so devs can exercise the heavy post-quantum contract
 * tests on demand without paying their cost every `npx vitest run`.
 *
 * Slow tests (SLH-DSA-verify-in-Bitcoin-Script, SPHINCSWallet,
 * post-quantum-slhdsa-naive-INSECURE) run actual SLH-DSA verification
 * inside the off-chain interpreter, which is genuinely expensive
 * (~100s per 6-test file). They are correctness-critical and must
 * run in CI, but should not block local iteration.
 *
 * Usage:
 *   import { runSlowTests } from 'runar-testing';
 *   describe.skipIf(!runSlowTests)('SPHINCSWallet (...)', () => { ... });
 *
 * To force-run locally:
 *   RUN_SLOW_TESTS=1 npx vitest run
 */

export const IS_CI =
  process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true';

export const runSlowTests = IS_CI || process.env.RUN_SLOW_TESTS === '1';
