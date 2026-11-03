/**
 * N-016 — execution proof, all seven tiers: a local that shares a property's
 * name no longer captures `this.<prop>`.
 *
 *     readonly target: bigint;
 *     public unlock(n: bigint) {
 *       const target = n + 1n;
 *       assert(target == this.target);     // the PROPERTY, per R8
 *     }
 *
 * Before the fix every tier compiled this to `8b769c` (OP_1ADD OP_DUP
 * OP_NUMEQUAL): the property read became a copy of the local, so the guard
 * compared the local with itself and ANY n unlocked the coins.
 *
 * The stateful case pins the write path and the state continuation:
 *
 *     count: bigint;
 *     public bump(n: bigint) {
 *       const count = n;
 *       assert(this.count == 5n);          // guard on the ON-CHAIN state
 *       this.count = this.count + count;   // new state = old state + n
 *     }
 *
 * Pre-fix `this.count` read the local, so the guard checked `n == 5` instead
 * of the state, and the continuation committed `n + n`.
 *
 * Oracle: the real `@bsv/sdk` Spend engine (`validateContractInput`, and the
 * SDK's pre-broadcast dry-run, which is the same engine). Each tier's CLI
 * artifact is deployed and called through the TS SDK. Every expected verdict
 * is derived BY HAND from the source above, never from compiler output.
 *
 * What this proves: for each of the seven tiers, the compiled script enforces
 * `n + 1 == target` (the crafted `n = 5` against `target = 10`, which the
 * pre-fix script accepted, is rejected; `n = 9` is accepted), and the stateful
 * script enforces the guard on the on-chain value (crafted `bump(5)` against
 * on-chain 7 is rejected) and commits `old + n` (honest `bump(3)` from 5 is
 * accepted with state 8).
 *
 * The last block pins the would-be conformance fixture `property-shadow` (a
 * stateful contract that reads a readonly property and reads + writes a
 * mutable one, each after a same-named local) CROSS-TIER: all seven tiers emit
 * byte-identical script hex in both constant-folding modes and identical
 * canonical ANF, and its spends are checked on the Spend engine. It stands in
 * for the fixture because adding a fixture re-stamps
 * `conformance/script-size-baseline.json` and
 * `packages/decompiler/coverage-baseline.json`, which need human-signed
 * provenance entries (see the N-016 report).
 * What it does NOT prove: the other shadowing shapes (if-arm, loop variable,
 * private helper, …) on chain — those are pinned byte-for-byte against their
 * renamed spellings by each tier's n016 unit test — or anything about a local
 * that collides with a compiler temp name.
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
const TMP = mkdtempSync(join(tmpdir(), 'runar-n016-'));

const STATELESS_SRC = `import { SmartContract, assert } from 'runar-lang';

class Sh extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public unlock(n: bigint) {
    const target = n + 1n;
    assert(target == this.target);
  }
}
`;

const STATEFUL_SRC = `import { StatefulSmartContract, assert } from 'runar-lang';

class ShW extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public bump(n: bigint) {
    const count = n;
    assert(this.count == 5n);
    this.count = this.count + count;
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

const TIERS: { name: string; artifact: (src: string, fileName: string) => RunarArtifact }[] = [
  {
    name: 'ts',
    artifact: (src, fileName) => {
      const r = compile(src, { fileName });
      if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
      return r.artifact as unknown as RunarArtifact;
    },
  },
  {
    name: 'go',
    artifact: (src, f) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', writeTmp(f, src)],
    )),
  },
  {
    name: 'rust',
    artifact: (src, f) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
      ['--source', writeTmp(f, src)],
    )),
  },
  {
    name: 'python',
    artifact: (src, f) => JSON.parse(run('python3', ['-m', 'runar_compiler', '--source', writeTmp(f, src)], join(REPO, 'compilers', 'python'))),
  },
  {
    name: 'zig',
    artifact: (src, f) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
      ['--source', writeTmp(f, src)],
    )),
  },
  {
    name: 'ruby',
    artifact: (src, f) => JSON.parse(run('ruby', [
      '-I', join(REPO, 'compilers', 'ruby', 'lib'),
      join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
      '--source', writeTmp(f, src),
    ])),
  },
  {
    name: 'java',
    artifact: (src, f) => {
      const out = writeTmp('artifact.json', '');
      run('java', ['-jar', javaJar(), '--source', writeTmp(f, src), '--emit-artifact', out]);
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

/** Deploy `artifact` with `ctorArgs`, call `method(args)`, and replay the
 *  contract input on the real Spend engine. */
async function spend(
  artifact: RunarArtifact,
  ctorArgs: bigint[],
  method: string,
  args: bigint[],
): Promise<Verdict> {
  const key = testKey('alice');
  const signer = new LocalSigner(key.privKey);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: key.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(key.pubKey),
  });
  const contract = new RunarContract(artifact, ctorArgs);
  await contract.deploy(provider, signer, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  try {
    // dryRun: the SDK replays the contract input on the real Spend engine
    // before broadcast and throws a message unique to a script rejection.
    await contract.call(method, args, provider, signer, { dryRun: true });
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

for (const tier of TIERS) {
  describe(`N-016 [${tier.name}] — this.<prop> reads the property, not a same-named local`, () => {
    const stateless = tier.artifact(STATELESS_SRC, 'Sh.runar.ts');
    const stateful = tier.artifact(STATEFUL_SRC, 'ShW.runar.ts');

    it('the stateless script is not the self-comparison 8b769c', () => {
      expect(stateless.script).not.toBe('8b769c');
    });

    it('ATTACK unlock(5) against target = 10 is REJECTED (5 + 1 != 10)', async () => {
      const v = await spend(stateless, [10n], 'unlock', [5n]);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted, 'the guard compared the local with itself').toBe(false);
    });

    it('honest unlock(9) against target = 10 is ACCEPTED', async () => {
      const v = await spend(stateless, [10n], 'unlock', [9n]);
      expect(v.accepted, v.error).toBe(true);
    });

    it('ATTACK bump(5) with on-chain count = 7 is REJECTED (the guard reads the state, not n)', async () => {
      const v = await spend(stateful, [7n], 'bump', [5n]);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted, 'the guard read the local instead of the on-chain count').toBe(false);
    });

    it('honest bump(3) with on-chain count = 5 is ACCEPTED and commits count = 8', async () => {
      const v = await spend(stateful, [5n], 'bump', [3n]);
      expect(v.accepted, v.error).toBe(true);
      expect(v.state).toEqual({ count: 8n });
    });
  });
}

// ---------------------------------------------------------------------------
// Cross-tier pin of the would-be conformance fixture `property-shadow`.
// ---------------------------------------------------------------------------

const FIXTURE_SRC = `import { StatefulSmartContract, assert } from 'runar-lang';

class PropertyShadow extends StatefulSmartContract {
  readonly target: bigint;
  count: bigint;

  constructor(target: bigint, count: bigint) {
    super(target, count);
    this.target = target;
    this.count = count;
  }

  public bump(n: bigint) {
    const target = n + 1n;
    assert(target == this.target);
    const count = n;
    this.count = this.count + count;
    assert(this.count > count);
  }
}
`;

const FIXTURE_FILE = 'PropertyShadow.runar.ts';

/** Native-tier CLI invocation (everything but the path and the mode flags). */
const NATIVE: Record<string, () => { cmd: string; pre: string[]; cwd?: string }> = {
  go: () => ({ cmd: requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'), pre: [] }),
  rust: () => ({ cmd: requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'), pre: [] }),
  python: () => ({ cmd: 'python3', pre: ['-m', 'runar_compiler'], cwd: join(REPO, 'compilers', 'python') }),
  zig: () => ({ cmd: requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'), pre: [] }),
  ruby: () => ({ cmd: 'ruby', pre: ['-I', join(REPO, 'compilers', 'ruby', 'lib'), join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')] }),
  java: () => ({ cmd: 'java', pre: ['-jar', javaJar()] }),
};

function nativeOut(tier: string, extra: string[], disableFold: boolean): string {
  const { cmd, pre, cwd } = NATIVE[tier]!();
  const fold = disableFold ? ['--disable-constant-folding'] : [];
  return run(cmd, [...pre, '--source', writeTmp(FIXTURE_FILE, FIXTURE_SRC), ...extra, ...fold], cwd).trim();
}

/** Sorted keys, no `sourceLoc`, integers as plain numbers — the conformance
 *  runner's canonical form, so tiers that spell a small integer as a JSON
 *  number and tiers that spell it `"5n"` compare equal. */
function canonical(value: unknown): unknown {
  if (typeof value === 'bigint') return Number(value);
  if (typeof value === 'string' && /^-?\d+n$/.test(value)) return Number(value.slice(0, -1));
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as object).sort()) {
      if (k === 'sourceLoc') continue;
      out[k] = canonical((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

describe('N-016 would-be fixture `property-shadow` — seven-tier parity', () => {
  const tierNames = ['ts', ...Object.keys(NATIVE)];

  for (const disableFold of [true, false]) {
    it(`all seven tiers emit identical script hex (fold ${disableFold ? 'off' : 'on'})`, () => {
      const ts = compile(FIXTURE_SRC, { fileName: FIXTURE_FILE, disableConstantFolding: disableFold });
      expect(ts.success, JSON.stringify(ts.diagnostics)).toBe(true);
      const hexes: Record<string, string> = { ts: ts.artifact!.script };
      for (const tier of Object.keys(NATIVE)) hexes[tier] = nativeOut(tier, ['--hex'], disableFold);
      for (const tier of tierNames) expect(hexes[tier], `${tier} diverges from ts`).toBe(hexes.ts);
    });
  }

  it('all seven tiers emit identical canonical ANF (fold off), binding the shadowing locals as <name>@local', () => {
    const ts = compile(FIXTURE_SRC, { fileName: FIXTURE_FILE, disableConstantFolding: true });
    const tsAnf = JSON.stringify(canonical(ts.anf));
    expect(tsAnf).toContain('"name":"target@local"');
    expect(tsAnf).toContain('"name":"count@local"');
    for (const tier of Object.keys(NATIVE)) {
      const anf = JSON.stringify(canonical(JSON.parse(nativeOut(tier, ['--emit-ir'], true))));
      expect(anf, `${tier} ANF diverges from ts`).toBe(tsAnf);
    }
  });

  for (const tier of TIERS) {
    const artifact = tier.artifact(FIXTURE_SRC, FIXTURE_FILE);

    it(`[${tier.name}] honest bump(9) with target = 10, count = 4 is ACCEPTED and commits count = 13`, async () => {
      const v = await spend(artifact, [10n, 4n], 'bump', [9n]);
      expect(v.accepted, v.error).toBe(true);
      expect(v.state).toEqual({ count: 13n });
    });

    it(`[${tier.name}] ATTACK bump(5) with target = 10 is REJECTED (5 + 1 != 10)`, async () => {
      const v = await spend(artifact, [10n, 4n], 'bump', [5n]);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted).toBe(false);
    });
  }
});
