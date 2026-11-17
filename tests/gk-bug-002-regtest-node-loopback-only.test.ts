/**
 * GK-BUG-002: the integration regtest node was reachable from the LAN.
 *
 * `integration/regtest.sh` published the RPC, P2P and ZMQ ports with a bare
 * `-p $PORT:$PORT`, which Docker binds on 0.0.0.0. Inside the container the
 * node runs `rpcbind=0.0.0.0` + `rpcallowip=0.0.0.0/0` with the well-known
 * `bitcoin:bitcoin` credentials (both are needed for Docker's port forwarding
 * to reach bitcoind at all), so anything on the host's network could drive the
 * node's wallet and RPC. The Teranode compose stack already publishes on
 * 127.0.0.1 only; this script did not.
 *
 * Two smaller defects rode along:
 *   - bitcoind was started without `-regtest`, so the network was decided only
 *     by whatever `bitcoin.conf` happened to sit in the data directory;
 *   - that conf was written only when absent, so a stale or hand-placed conf
 *     (e.g. one predating a change to this script) was used as-is forever.
 *
 * The fix: every published port is bound to 127.0.0.1, bitcoind gets an
 * explicit `-regtest`, and the conf is rewritten on every start.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, resolve } from 'node:path';

const ROOT = resolve(__dirname, '..');
const REGTEST = 'integration/regtest.sh';

const read = (rel: string) => readFileSync(join(ROOT, rel), 'utf8');

/** Join backslash-continued lines so one `docker run` is one logical line. */
function logicalLines(text: string): string[] {
  return text.replace(/\\\n/g, ' ').split('\n');
}

/** Every `-p <spec>` argument on every `docker run` line of a script. */
function publishSpecs(text: string): string[] {
  const out: string[] = [];
  for (const line of logicalLines(text)) {
    if (!/\bdocker run\b/.test(line)) continue;
    for (const m of line.matchAll(/(?:^|\s)(?:-p|--publish)[\s=]+(\S+)/g)) out.push(m[1]!);
  }
  return out;
}

/** Tracked shell scripts that start a container. */
function scriptsWithDockerRun(): string[] {
  const files = execFileSync('git', ['ls-files', '*.sh'], { cwd: ROOT, encoding: 'utf8' })
    .split('\n')
    .filter(Boolean);
  return files.filter((f) => existsSync(join(ROOT, f)) && /\bdocker run\b/.test(read(f)));
}

describe('GK-BUG-002: regtest nodes are published on loopback only', () => {
  it('the integration regtest script is where the test thinks it is', () => {
    expect(existsSync(join(ROOT, REGTEST)), `${REGTEST} moved`).toBe(true);
    expect(publishSpecs(read(REGTEST)).length, 'no -p publishes found in regtest.sh').toBeGreaterThanOrEqual(3);
  });

  it('every docker -p publish in every tracked script binds 127.0.0.1', () => {
    const scripts = scriptsWithDockerRun();
    expect(scripts).toContain(REGTEST);
    const offenders: string[] = [];
    for (const f of scripts) {
      for (const spec of publishSpecs(read(f))) {
        if (!spec.startsWith('127.0.0.1:')) offenders.push(`${f}: -p ${spec}`);
      }
    }
    expect(offenders, 'these publishes bind every host interface (0.0.0.0)').toEqual([]);
  });

  it('bitcoind is started with an explicit -regtest', () => {
    const launches = logicalLines(read(REGTEST)).filter((l) => /\bbitcoind\b/.test(l));
    expect(launches.length).toBeGreaterThan(0);
    for (const l of launches) {
      expect(l, `bitcoind launched without -regtest: ${l.trim()}`).toMatch(/\bbitcoind\s+(?:\S+\s+)*-regtest\b/);
    }
  });

  it('bitcoin.conf is rewritten on every start, never reused when present', () => {
    const text = read(REGTEST);
    expect(text, 'the conf write is guarded by an "only if absent" test').not.toMatch(
      /if\s+\[\s*!\s*-f\s+[^\]]*bitcoin\.conf/,
    );
    expect(text).toMatch(/cat\s+<<\s*EOL\s*>\s*\S*bitcoin\.conf/);
    expect(text).toMatch(/^regtest=1$/m);
  });

  // Because the conf is rewritten on every start, the node's RPC credentials
  // must come from the same variables every tier's client reads (RPC_USER /
  // RPC_PASS, default bitcoin/bitcoin). Hard-coding bitcoin/bitcoin here made
  // CI's integration job (RPC_USER=regtest) see a 401 and report "Regtest node
  // not running" although the node was up.
  it('the conf takes its RPC credentials from RPC_USER / RPC_PASS', () => {
    const text = read(REGTEST);
    expect(text).toMatch(/^rpcuser=\$\{RPC_USER:-bitcoin\}$/m);
    expect(text).toMatch(/^rpcpassword=\$\{RPC_PASS:-bitcoin\}$/m);
    expect(text, 'a hard-coded rpcuser ignores RPC_USER').not.toMatch(/^rpcuser=bitcoin$/m);
  });

  it('no workflow pre-writes the bitcoin.conf that regtest.sh overwrites', () => {
    const workflows = execFileSync('git', ['ls-files', '.github/workflows/*.yml'], { cwd: ROOT, encoding: 'utf8' })
      .split('\n')
      .filter(Boolean);
    const offenders = workflows.filter((f) => /regtest-data\/[^\s'"]*bitcoin\.conf/.test(read(f)));
    expect(offenders, 'a pre-written conf is silently replaced at start; set RPC_USER/RPC_PASS instead').toEqual([]);
  });
});
