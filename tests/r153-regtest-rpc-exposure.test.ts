/**
 * R-153 (CL-BUG-082): the blackjack demo's regtest.sh writes a bitcoin.conf
 * with `rpcallowip=0.0.0.0/0` and publishes the RPC port on every interface
 * (`-p 18332:18332`), with the credentials the same script writes into the file
 * (`rpcuser=bitcoin` / `rpcpassword=bitcoin`) and which both webapps default to.
 *
 * The funds are regtest, so nothing is at stake in the demo itself. What is at
 * stake is that this is a copy-paste template: run it on a laptop on a café
 * network and anyone on that network has authenticated RPC on your node; run it
 * on a cloud box with a public IP and it is on the internet. "It is only
 * regtest" holds until someone changes one line to testnet and keeps the rest.
 *
 * The fix keeps the demo working. `rpcbind=0.0.0.0` stays — a container process
 * must listen on all of ITS interfaces to receive forwarded traffic — and the
 * exposure is closed on the two layers that actually decide reachability:
 * `rpcallowip` narrowed to loopback plus the Docker bridge range, and the
 * published ports bound to 127.0.0.1.
 *
 * The script is not executed in CI, so this reads it. That is the weaker kind of
 * test and it is the honest one here: asserting on the text is exactly what the
 * finding is about — the shape of a file a reader will copy.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = 'examples/end2end-example/webapp-blackjack/regtest.sh';

const script = () => readFileSync(join(ROOT, SCRIPT), 'utf8');

describe('R-153: the regtest demo does not expose its node to the network', () => {
  it('the script is where the test thinks it is', () => {
    expect(existsSync(join(ROOT, SCRIPT)), `${SCRIPT} moved`).toBe(true);
    expect(script()).toContain('rpcuser=bitcoin');
  });

  it('does not allow RPC from every address', () => {
    const offenders = script()
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => /^rpcallowip=0\.0\.0\.0\/0/.test(l));
    expect(
      offenders,
      'rpcallowip=0.0.0.0/0 accepts authenticated RPC from anyone who can route to the port',
    ).toEqual([]);
  });

  it('publishes every container port on loopback only', () => {
    const runLine = script()
      .split('\n')
      .find((l) => l.includes('docker run') && l.includes('bitcoin-sv'));
    expect(runLine, 'the docker run line is gone — update this test').toBeDefined();

    const published = [...runLine!.matchAll(/-p\s+(\S+)/g)].map((m) => m[1]!);
    expect(published.length, 'no -p mappings found').toBeGreaterThan(0);

    const exposed = published.filter((p) => !p.startsWith('127.0.0.1:'));
    expect(
      exposed,
      'these ports are published on every interface; bind them to 127.0.0.1',
    ).toEqual([]);
  });

  it('still allows the loopback and Docker-bridge clients the demo needs', () => {
    const text = script();
    expect(text, 'the container must still accept the forwarded connection').toMatch(
      /rpcallowip=127\.0\.0\.1/,
    );
    expect(text, 'Docker forwards from the bridge gateway, not from 127.0.0.1').toMatch(
      /rpcallowip=172\.16\.0\.0\/12/,
    );
    // The bind stays: a container process that listens only on loopback cannot
    // receive a forwarded connection at all.
    expect(text).toMatch(/rpcbind=0\.0\.0\.0/);
  });
});
