/**
 * F-054 — the offline Rust integration tests had no runner.
 *
 * `integration/rust/tests/` holds two kinds of `#[test]`: on-chain ones gated
 * with `#[cfg_attr(not(feature = "regtest"), ignore)]`, and offline compile /
 * script-size checks (blake3, slhdsa, wots, sha256_compress, p256/p384 wallets,
 * schnorr_zkp, ...) that carry no gate. Every runner of the suite invoked
 * `cargo test --release -- --ignored`, and libtest's `--ignored` runs ONLY the
 * ignored tests. The offline checks therefore ran nowhere: not in CI, not in
 * `pnpm run integration:rust`, not in `integration/run-all*.sh`.
 *
 * What this proves: every runner invocation of the integration/rust suite in
 * those four files exists (so the check is not vacuous) and does not narrow the
 * run with a bare `--ignored`, i.e. it executes both the gated and the ungated
 * tests.
 *
 * What it does not prove: that the tests pass, that a runner exists in some
 * other script added later, or that the offline tests are meaningful. It also
 * does not inspect `#[ignore]` placement inside the Rust files.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf-8');

/** Lines that run `cargo test` for the integration/rust crate. */
function rustIntegrationRunners(text: string, inIntegrationDir: boolean): string[] {
  return text
    .split('\n')
    .filter((l) => /cargo test/.test(l))
    .filter((l) => (inIntegrationDir ? /\bcd rust\b/.test(l) : /cd integration\/rust\b/.test(l)));
}

/** True when the libtest args restrict the run to ignored tests only. */
const onlyIgnored = (line: string) => /(^|\s)--ignored(?![\w-])/.test(line);

const SOURCES: Array<{ file: string; inIntegrationDir: boolean }> = [
  { file: '.github/workflows/ci.yml', inIntegrationDir: false },
  { file: 'package.json', inIntegrationDir: false },
  { file: 'integration/run-all.sh', inIntegrationDir: true },
  { file: 'integration/run-all-parallel.sh', inIntegrationDir: true },
];

describe('F-054: integration/rust runners execute the ungated (offline) tests', () => {
  for (const { file, inIntegrationDir } of SOURCES) {
    it(`${file} runs integration/rust without a bare --ignored filter`, () => {
      const runners = rustIntegrationRunners(read(file), inIntegrationDir);
      expect(runners.length, `${file}: no integration/rust cargo test runner found`).toBeGreaterThan(0);
      for (const line of runners) {
        expect(onlyIgnored(line), `${file}: "${line.trim()}" runs only #[ignore]d tests`).toBe(false);
      }
    });
  }
});
