/**
 * N-007 — every tier: a method parameter that shadows a MUTABLE property was
 * read from the stale on-chain STATE inside an `if` arm, not from the caller's
 * witness argument. A guard in the arm therefore checked the wrong value:
 *
 *     count: bigint;                                  // on-chain state = 5
 *     public set(count: bigint, flag: boolean) {
 *       if (flag) { assert(count == 5n); }            // the ARGUMENT must be 5
 *       this.count = count;
 *     }
 *
 * The source says `set(7n, true)` must fail (`7 == 5` is false). F-015 fixed
 * Python (and Java's `subContext` already copied the map); TS, Go, Rust, Zig
 * and Ruby still lowered the arm in a fresh context with an EMPTY
 * `renamedParams`, so `load_param('count')` resolved to the deserialized
 * property slot and the attacker's spend was ACCEPTED, moving the state to 7
 * past a guard that forbids it.
 *
 * The acceptance oracle is the real `@bsv/sdk` `Spend` engine: each tier's
 * artifact is deployed and called through the TS SDK, and the call's contract
 * input is replayed with `validateContractInput`. Expected verdicts are
 * derived BY HAND from the source, never from compiler output.
 *
 * What this proves: for each of the seven tiers, the compiled script enforces
 * an in-arm guard on the caller's argument, rejects the crafted shadow-read
 * attack, and still accepts the honest and skip-arm spends with the correct
 * continuation state; and all seven emit the same bytes.
 * What it does NOT prove: shadowing shapes other than this probe (the per-tier
 * `n007` alpha-rename tests cover else/ternary arms), or hostile `--ir` input.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n007-'));
const FILE = 'Probe.runar.ts';

const SRC = `import { StatefulSmartContract, assert } from 'runar-lang';

class Probe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(count == 5n);
    }
    this.count = count;
  }
}
`;

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `gradle jar` in compilers/java');
  return join(libs, jar);
}

function run(cmd: string, args: string[], cwd?: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 32 * 1024 * 1024 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}: ${r.stderr}`);
  return r.stdout;
}

let seq = 0;
function writeTmp(fileName: string, src: string): string {
  const dir = join(TMP, String(seq++));
  mkdirSync(dir);
  const p = join(dir, fileName);
  writeFileSync(p, src);
  return p;
}

const TIERS: { name: string; artifact: () => RunarArtifact }[] = [
  {
    name: 'ts',
    artifact: () => {
      const r = compile(SRC, { fileName: FILE });
      if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
      return r.artifact as unknown as RunarArtifact;
    },
  },
  {
    name: 'go',
    artifact: () => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', writeTmp(FILE, SRC)],
    )),
  },
  {
    name: 'rust',
    artifact: () => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
      ['--source', writeTmp(FILE, SRC)],
    )),
  },
  {
    name: 'python',
    artifact: () => JSON.parse(run('python3', ['-m', 'runar_compiler', '--source', writeTmp(FILE, SRC)], join(REPO, 'compilers', 'python'))),
  },
  {
    name: 'zig',
    artifact: () => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
      ['--source', writeTmp(FILE, SRC)],
    )),
  },
  {
    name: 'ruby',
    artifact: () => JSON.parse(run('ruby', [
      '-I', join(REPO, 'compilers', 'ruby', 'lib'),
      join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
      '--source', writeTmp(FILE, SRC),
    ])),
  },
  {
    name: 'java',
    artifact: () => {
      const out = writeTmp('artifact.json', '');
      run('java', ['-jar', javaJar(), '--source', writeTmp(FILE, SRC), '--emit-artifact', out]);
      return JSON.parse(readFileSync(out, 'utf8'));
    },
  },
];

interface Verdict {
  accepted: boolean;
  reachedEngine: boolean;
  error?: string;
  state?: Record<string, unknown>;
}

/** Deploy with on-chain `count = state`, call `set`, and replay the contract
 *  input on the real Spend engine. */
async function spend(artifact: RunarArtifact, state: bigint, count: bigint, flag: boolean): Promise<Verdict> {
  const key = testKey('alice');
  const signer = new LocalSigner(key.privKey);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: key.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(key.pubKey),
  });
  const contract = new RunarContract(artifact, [state]);
  await contract.deploy(provider, signer, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  try {
    // dryRun: the SDK replays the contract input on the real Spend engine
    // before broadcast and throws a message unique to a script rejection.
    await contract.call('set', [count, flag], provider, signer, { dryRun: true });
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return {
      accepted: false,
      reachedEngine: error.includes('local pre-broadcast dry-run rejected the primary contract input'),
      error,
    };
  }
  const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
  return {
    accepted: validateContractInput(callTx, 0, deployTx, 0),
    reachedEngine: true,
    state: contract.state as Record<string, unknown>,
  };
}

const artifacts = new Map(TIERS.map((t) => [t.name, t.artifact()]));

describe('N-007 — all seven tiers emit the same script for the probe', () => {
  it('every tier matches ts byte for byte', () => {
    const ts = artifacts.get('ts')!.script;
    for (const [name, a] of artifacts) expect(a.script, `${name} diverges from ts`).toBe(ts);
  });
});

for (const [name, artifact] of artifacts) {
  describe(`N-007 [${name}] — a shadowing param read inside an if-arm is the witness argument`, () => {
    const STATE = 5n;

    it('ATTACK set(7, true) with on-chain count = 5 is REJECTED (the arm must check 7, not the state)', async () => {
      const v = await spend(artifact, STATE, 7n, true);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted, 'the arm read the stale state value instead of the argument').toBe(false);
    });

    it('honest set(5, true) is ACCEPTED and commits count = 5', async () => {
      const v = await spend(artifact, STATE, 5n, true);
      expect(v.accepted, v.error).toBe(true);
      expect(v.state).toEqual({ count: 5n });
    });

    it('CONTROL set(7, false) skips the arm, is ACCEPTED and commits count = 7', async () => {
      const v = await spend(artifact, STATE, 7n, false);
      expect(v.accepted, v.error).toBe(true);
      expect(v.state).toEqual({ count: 7n });
    });

    it('CONTROL on-chain count = 7: honest set(5, true) is ACCEPTED (guard reads the argument, not the state)', async () => {
      const v = await spend(artifact, 7n, 5n, true);
      expect(v.accepted, v.error).toBe(true);
      expect(v.state).toEqual({ count: 5n });
    });
  });
}
