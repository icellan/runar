/**
 * N-483: the Rust BRC-100 wallet-client live test must fail closed.
 *
 * `pnpm run wallet-client:rust` (and the CI integration job, since N-480) runs
 * `cargo test --test wallet_client_integration -- --ignored`. The test used to
 * `return` early when RUNAR_WALLET_ENDPOINT was unset, so selecting it with
 * --ignored and no wallet reported PASS without exercising anything.
 *
 * Proves: with the test explicitly selected via --ignored and the endpoint
 * env var removed, cargo exits non-zero and the output names the variable.
 * Does NOT prove: the with-endpoint path (covered by running the mock wallet,
 * integration/mock-wallet/mock-wallet.sh, in the CI integration job).
 */
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const REPO = resolve(__dirname, '..');

describe('N-483: Rust wallet-client live test is fail-closed', () => {
  it('fails (not passes) under --ignored when RUNAR_WALLET_ENDPOINT is unset', () => {
    const env = { ...process.env };
    delete env.RUNAR_WALLET_ENDPOINT;
    const r = spawnSync(
      'cargo',
      ['test', '--test', 'wallet_client_integration', '--', '--ignored'],
      { cwd: resolve(REPO, 'packages/runar-rs'), env, encoding: 'utf8' },
    );
    const out = `${r.stdout}\n${r.stderr}`;
    expect(r.status, out).not.toBe(0);
    expect(out).toContain('RUNAR_WALLET_ENDPOINT');
  }, 600_000);
});
