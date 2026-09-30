/**
 * F-081 — every tier: `checkMultiSig(sigs, pks)` over arrays declared BEFORE a
 * control-flow construct failed to compile when the call sat inside it.
 *
 *     const sigs = [sig1];
 *     const pks = [this.pk1, this.pk2];
 *     if (mode == 1n) { assert(checkMultiSig(sigs, pks)); } else { ... }
 *
 * An `array_literal` binding is metadata only in the stack lowerer (its
 * elements stay individual stack slots, pulled to the top at the
 * checkMultiSig site). Two things were lost at a scope boundary, in all seven
 * tiers alike:
 *
 *   1. the `if` arms lowered in a FRESH context whose array metadata was
 *      empty, so the call threw "checkMultiSig: array_literal metadata
 *      missing" (then-arm, else-arm, nested arms);
 *   2. element liveness did not see through the array: `const sigs = [..]`
 *      is `t = array_literal` plus the alias `sigs = @ref:t`, and last-use
 *      propagation only followed `t`; an arm / loop body also saw only its
 *      OWN bindings. The elements had no last-use entry and were consumed at
 *      the first read — a second call (straight-line, in one arm, in a
 *      two-iteration loop, or after the loop) then failed with
 *      "value 't0' not found on stack".
 *
 * The acceptance oracle is the real `@bsv/sdk` `Spend` engine: each tier's
 * artifact is deployed and called through the TS SDK (the signature is a
 * real ECDSA signature over the real BIP-143 sighash), and the call's contract
 * input is replayed with `validateContractInput`. Expected verdicts are
 * derived BY HAND from the source (1-of-2 over {alice, bob}), never from
 * compiler output.
 *
 * What this proves: for each of the seven tiers and each shape (then-arm,
 * else-arm, nested arms, two calls in one arm, a two-iteration loop, an array
 * reused after the loop), the contract compiles, all seven emit the same
 * bytes as TS, the honest spend is ACCEPTED and a spend signed by a key that
 * is not committed (dave) is REJECTED by the real engine.
 * What it does NOT prove: arrays declared INSIDE an arm and used after it,
 * arrays passed into private methods, or hostile `--ir` input.
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
const TMP = mkdtempSync(join(tmpdir(), 'runar-f081-'));

const HEADER = `import { SmartContract, assert, PubKey, Sig, checkMultiSig } from 'runar-lang';

class Probe extends SmartContract {
  readonly pk1: PubKey;
  readonly pk2: PubKey;

  constructor(pk1: PubKey, pk2: PubKey) {
    super(pk1, pk2);
    this.pk1 = pk1;
    this.pk2 = pk2;
  }
`;

const ARRAYS = `    const sigs = [sig1];
    const pks = [this.pk1, this.pk2];
`;

/** Each shape: its method body, and the `mode` argument that routes the
 *  spend through the checkMultiSig site. */
const SHAPES: { name: string; body: string; mode: bigint }[] = [
  {
    // Compiled before the fix too: pins that the harness itself accepts and
    // rejects correctly, independent of the branch/loop shapes below.
    name: 'CONTROL straight-line',
    mode: 1n,
    body: `${ARRAYS}    assert(mode == 1n);
    assert(checkMultiSig(sigs, pks));
`,
  },
  {
    name: 'straight-line reuse',
    mode: 1n,
    body: `${ARRAYS}    assert(mode == 1n);
    assert(checkMultiSig(sigs, pks));
    assert(checkMultiSig(sigs, pks));
`,
  },
  {
    name: 'then-arm',
    mode: 1n,
    body: `${ARRAYS}    if (mode == 1n) {
      assert(checkMultiSig(sigs, pks));
    } else {
      assert(mode == 2n);
    }
`,
  },
  {
    name: 'else-arm',
    mode: 1n,
    body: `${ARRAYS}    if (mode == 2n) {
      assert(mode == 2n);
    } else {
      assert(checkMultiSig(sigs, pks));
    }
`,
  },
  {
    name: 'nested arms',
    mode: 1n,
    body: `${ARRAYS}    if (mode > 0n) {
      if (mode == 1n) {
        assert(checkMultiSig(sigs, pks));
      } else {
        assert(mode == 2n);
      }
    } else {
      assert(false);
    }
`,
  },
  {
    name: 'two calls in one arm',
    mode: 1n,
    body: `${ARRAYS}    if (mode == 1n) {
      assert(checkMultiSig(sigs, pks));
      assert(checkMultiSig(sigs, pks));
    } else {
      assert(mode == 2n);
    }
`,
  },
  {
    name: 'two-iteration loop',
    mode: 1n,
    body: `${ARRAYS}    let ok = mode == 1n;
    for (let i = 0n; i < 2n; i++) {
      ok = ok && checkMultiSig(sigs, pks);
    }
    assert(ok);
`,
  },
  {
    name: 'array reused after the loop',
    mode: 1n,
    body: `${ARRAYS}    let ok = mode == 1n;
    for (let i = 0n; i < 1n; i++) {
      ok = ok && checkMultiSig(sigs, pks);
    }
    assert(ok);
    assert(checkMultiSig(sigs, pks));
`,
  },
];

function sourceOf(body: string): string {
  return `${HEADER}
  public unlock(sig1: Sig, mode: bigint) {
${body}  }
}
`;
}

const FILE = 'Probe.runar.ts';

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
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}: ${r.stderr || r.stdout}`);
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

const TIERS: { name: string; artifact: (src: string) => RunarArtifact }[] = [
  {
    name: 'ts',
    artifact: (src) => {
      const r = compile(src, { fileName: FILE });
      if (!r.success || !r.artifact) {
        throw new Error(JSON.stringify(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message)));
      }
      return r.artifact as unknown as RunarArtifact;
    },
  },
  {
    name: 'go',
    artifact: (src) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', writeTmp(FILE, src)],
    )),
  },
  {
    name: 'rust',
    artifact: (src) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
      ['--source', writeTmp(FILE, src)],
    )),
  },
  {
    name: 'python',
    artifact: (src) => JSON.parse(run('python3', ['-m', 'runar_compiler', '--source', writeTmp(FILE, src)], join(REPO, 'compilers', 'python'))),
  },
  {
    name: 'zig',
    artifact: (src) => JSON.parse(run(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'),
      ['--source', writeTmp(FILE, src)],
    )),
  },
  {
    name: 'ruby',
    artifact: (src) => JSON.parse(run('ruby', [
      '-I', join(REPO, 'compilers', 'ruby', 'lib'),
      join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
      '--source', writeTmp(FILE, src),
    ])),
  },
  {
    name: 'java',
    artifact: (src) => {
      const out = writeTmp('artifact.json', '');
      run('java', ['-jar', javaJar(), '--source', writeTmp(FILE, src), '--emit-artifact', out]);
      return JSON.parse(readFileSync(out, 'utf8'));
    },
  },
];

interface Verdict {
  accepted: boolean;
  reachedEngine: boolean;
  error?: string;
}

/** Deploy locked to {alice, bob}, spend with a signature from `signerName`,
 *  and replay the contract input on the real Spend engine. */
async function spend(artifact: RunarArtifact, signerName: string, mode: bigint): Promise<Verdict> {
  const funder = testKey('alice');
  const fundSigner = new LocalSigner(funder.privKey);
  const callKey = testKey(signerName);
  const callSigner = new LocalSigner(callKey.privKey);
  const provider = new MockProvider();
  for (const [k, s] of [[funder, fundSigner], [callKey, callSigner]] as const) {
    provider.addUtxo(await s.getAddress(), {
      txid: k.privKey.slice(0, 64),
      outputIndex: 0,
      satoshis: 500_000,
      script: buildP2PKHScript(k.pubKey),
    });
  }
  const contract = new RunarContract(artifact, [testKey('alice').pubKey, testKey('bob').pubKey]);
  await contract.deploy(provider, fundSigner, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  try {
    // `null` Sig = auto-signed by the call signer over the real sighash.
    await contract.call('unlock', [null, mode], provider, callSigner, { dryRun: true });
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return {
      accepted: false,
      reachedEngine: error.includes('local pre-broadcast dry-run rejected the primary contract input'),
      error,
    };
  }
  const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
  return { accepted: validateContractInput(callTx, 0, deployTx, 0), reachedEngine: true };
}

for (const shape of SHAPES) {
  const src = sourceOf(shape.body);
  describe(`F-081 [${shape.name}] — checkMultiSig over arrays declared outside the construct`, () => {
    const artifacts = new Map<string, RunarArtifact>();
    const errors = new Map<string, string>();
    for (const t of TIERS) {
      try {
        artifacts.set(t.name, t.artifact(src));
      } catch (e) {
        errors.set(t.name, e instanceof Error ? e.message : String(e));
      }
    }

    it('compiles in all seven tiers', () => {
      expect(Object.fromEntries(errors)).toEqual({});
    });

    it('every tier matches ts byte for byte', () => {
      const ts = artifacts.get('ts');
      expect(ts, 'ts failed to compile').toBeDefined();
      for (const [name, a] of artifacts) expect(a.script, `${name} diverges from ts`).toBe(ts!.script);
    });

    for (const t of TIERS) {
      it(`[${t.name}] honest spend (alice) is ACCEPTED`, async () => {
        const a = artifacts.get(t.name);
        expect(a, errors.get(t.name)).toBeDefined();
        const v = await spend(a!, 'alice', shape.mode);
        expect(v.accepted, v.error).toBe(true);
      });

      it(`[${t.name}] ATTACK: a signature from an uncommitted key (dave) is REJECTED`, async () => {
        const a = artifacts.get(t.name);
        expect(a, errors.get(t.name)).toBeDefined();
        const v = await spend(a!, 'dave', shape.mode);
        expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
        expect(v.accepted).toBe(false);
      });
    }
  });
}
