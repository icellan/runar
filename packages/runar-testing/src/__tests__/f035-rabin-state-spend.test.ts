/**
 * F-035 — execution proof: a stateful contract with mutable `RabinPubKey` and
 * `RabinSig` fields is deployable and spendable through the SDK, on each
 * compiler tier's own artifact, in both constant-folding modes.
 *
 *     oracleKey: RabinPubKey;  lastSig: RabinSig;  count: bigint;
 *     public rotate(nextKey: RabinPubKey, nextSig: RabinSig) {
 *       assert(nextKey > 0n);
 *       this.oracleKey = nextKey; this.lastSig = nextSig; this.count++;
 *     }
 *
 * (conformance/sdk-output/contracts/RabinState.runar.ts — the same contract the
 * `state-rabin` sdk-output fixture deploys through all seven SDKs.)
 *
 * Every compiler stores a Rabin field like `bigint`: OP_NUM2BIN 8 on write and
 * an 8-byte slice on read, so the state section is three 8-byte words. Before
 * F-035 the shared STATE_FIELD_WIDTHS table and all seven SDK codecs lacked
 * both types and push-data framed them. Measured through the sdk-output tools:
 * TS / Go / Java wrote the DECIMAL text of the number as "hex" (not hex at
 * all), Python / Ruby / Zig wrote OP_0 for each field (the value is lost), and
 * Rust panicked. None of those deploys can be spent.
 *
 * Oracle: @bsv/sdk's production Spend with strict consensus flags (the SDK's
 * `dryRun` replay of input 0, then `validateContractInput`). The expected state
 * bytes are derived BY HAND from the num2bin-le8 encoding:
 *
 *   0x1234567890ABCDEF -> efcdab9078563412     -1000000007 -> 07ca9a3b00000080
 *   3 -> 0300000000000000                      4 -> 0400000000000000
 *   0x0BADC0FFEE123456 -> 563412eeffc0ad0b     -42 -> 2a00000000000080
 *
 * THE PRE-FIX LAYOUT. The near-misses below build the continuation with the
 * pre-F-035 codec behaviour (a Rabin field handled as push data, exactly like
 * ByteString), with the Rabin values handed over in the two shapes a pre-fix
 * SDK could actually put on chain: an 8-byte word framed as push data (`08 <word>`,
 * what the old TS codec wrote for a hex value) and an empty push (`00`, what
 * the old Python / Ruby / Zig codecs wrote for an integer). The covenant must
 * reject both: it rebuilds its continuation with OP_NUM2BIN 8, so a framed
 * continuation can never match hash256(outputs).
 *
 * What this proves: for every tier and both folding modes, the SDK deploys the
 * hand-derived 8-byte Rabin layout, an honest `rotate` is ACCEPTED under strict
 * Spend with the state carried through, and a second `rotate` spending the
 * SDK-built continuation is ACCEPTED too (the next spend parses what the SDK
 * wrote); both pre-fix layouts are REJECTED. The sdk-output block proves the
 * exact locking script all seven SDKs agree on (`state-rabin`'s
 * expected-locking.hex) is the one deployed here and is spendable.
 * What it does NOT prove: a CALL built by the six non-TS SDKs (their deploy
 * bytes are pinned by sdk-output, and their codecs by a byte-exact test per
 * tier); and nothing about Rabin values of 2^63 or more, which the compiler's
 * OP_NUM2BIN 8 cannot hold — every SDK refuses those.
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
const TMP = mkdtempSync(join(tmpdir(), 'runar-f035-'));
const SDK_OUTPUT = join(REPO, 'conformance', 'sdk-output');
const SRC = readFileSync(join(SDK_OUTPUT, 'contracts', 'RabinState.runar.ts'), 'utf8');
const FILE = 'RabinState.runar.ts';

const OWNER = testKey('alice');
const DEPLOY_SATS = 100_000;

const CTOR = [0x1234567890abcdefn, -1000000007n, 3n];
const STATE0 = 'efcdab9078563412' + '07ca9a3b00000080' + '0300000000000000';
const NEXT_KEY = 0x0badc0ffee123456n;
const NEXT_SIG = -42n;
const STATE1 = '563412eeffc0ad0b' + '2a00000000000080' + '0400000000000000';
const STATE2 = '563412eeffc0ad0b' + '2a00000000000080' + '0500000000000000';

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
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 180_000, maxBuffer: 64 * 1024 * 1024 });
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

/** Native-tier CLI invocation (everything but the source path and flags). */
const NATIVE: Record<string, () => { cmd: string; pre: string[]; cwd?: string }> = {
  go: () => ({ cmd: requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'), pre: [] }),
  rust: () => ({ cmd: requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'), pre: [] }),
  python: () => ({ cmd: 'python3', pre: ['-m', 'runar_compiler'], cwd: join(REPO, 'compilers', 'python') }),
  zig: () => ({ cmd: requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'), pre: [] }),
  ruby: () => ({ cmd: 'ruby', pre: ['-I', join(REPO, 'compilers', 'ruby', 'lib'), join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')] }),
  java: () => ({ cmd: 'java', pre: ['-jar', javaJar()] }),
};

function artifactFor(tier: string, disableFold: boolean): RunarArtifact {
  if (tier === 'ts') {
    const r = compile(SRC, { fileName: FILE, disableConstantFolding: disableFold });
    if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
    return r.artifact as unknown as RunarArtifact;
  }
  const { cmd, pre, cwd } = NATIVE[tier]!();
  const fold = disableFold ? ['--disable-constant-folding'] : [];
  const p = writeTmp(FILE, SRC);
  if (tier === 'java') {
    const out = writeTmp('artifact.json', '');
    run(cmd, [...pre, '--source', p, '--emit-artifact', out, ...fold], cwd);
    return JSON.parse(readFileSync(out, 'utf8'));
  }
  return JSON.parse(run(cmd, [...pre, '--source', p, ...fold], cwd));
}

interface Session {
  provider: MockProvider;
  contract: RunarContract;
  prevTx: Transaction;
}

async function deploy(artifact: RunarArtifact): Promise<Session> {
  const provider = new MockProvider();
  const s = new LocalSigner(OWNER.privKey);
  provider.addUtxo(await s.getAddress(), {
    txid: OWNER.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 5_000_000,
    script: buildP2PKHScript(OWNER.pubKey),
  });
  const contract = new RunarContract(artifact, CTOR);
  await contract.deploy(provider, s, { satoshis: DEPLOY_SATS });
  const prevTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  return { provider, contract, prevTx };
}

interface Step {
  accepted: boolean;
  reachedEngine: boolean;
  error?: string;
  continuation?: string;
}

async function rotate(s: Session, newState?: Record<string, unknown>): Promise<Step> {
  const before = s.provider.getBroadcastedTxs().length;
  try {
    await s.contract.call('rotate', [NEXT_KEY, NEXT_SIG], s.provider, new LocalSigner(OWNER.privKey), {
      dryRun: true,
      satoshis: DEPLOY_SATS,
      ...(newState ? { newState } : {}),
    });
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return {
      accepted: false,
      reachedEngine: error.includes('local pre-broadcast dry-run rejected the primary contract input'),
      error: error.slice(0, 400),
    };
  }
  const tx = Transaction.fromHex(s.provider.getBroadcastedTxs()[before]!);
  const accepted = validateContractInput(tx, 0, s.prevTx, 0);
  s.prevTx = tx;
  return { accepted, reachedEngine: true, continuation: tx.outputs[0]!.lockingScript.toHex() };
}

/**
 * The pre-F-035 SDK codec. With no width-table row for either Rabin type, every
 * codec sent a Rabin field down its push-data branch, i.e. handled it exactly
 * as a `ByteString`. Retyping the two state fields to `ByteString` on the
 * contract's own artifact (after an honest deploy) makes the TS SDK build the
 * call's continuation the way that codec did; nothing else in the call reads
 * `stateFields[].type`.
 */
async function withPreFixCodec<T>(s: Session, fn: () => Promise<T>): Promise<T> {
  const fields = s.contract.artifact.stateFields!;
  const saved = fields.map((f) => f.type);
  for (const f of fields) if (f.type === 'RabinPubKey' || f.type === 'RabinSig') f.type = 'ByteString';
  try {
    return await fn();
  } finally {
    fields.forEach((f, i) => { f.type = saved[i]!; });
  }
}

const TIERS = ['ts', ...Object.keys(NATIVE)];

for (const tier of TIERS) {
  for (const disableFold of [true, false]) {
    describe(`F-035 [${tier}, fold ${disableFold ? 'off' : 'on'}] — Rabin state fields are 8-byte words`, () => {
      const artifact = artifactFor(tier, disableFold);

      it('deploys the hand-derived layout; rotate ACCEPTED twice, state carried through', async () => {
        const s = await deploy(artifact);
        const deployed = s.prevTx.outputs[0]!.lockingScript.toHex();
        expect(deployed.endsWith('6a' + STATE0), `deployed state tail: ${deployed.slice(-60)}`).toBe(true);

        const r1 = await rotate(s);
        expect(r1.accepted, `honest rotate must be accepted: ${r1.error}`).toBe(true);
        expect(r1.continuation!.endsWith('6a' + STATE1)).toBe(true);
        expect(s.contract.state).toEqual({ oracleKey: NEXT_KEY, lastSig: NEXT_SIG, count: 4n });

        // The next spend reads the continuation the SDK just wrote.
        const r2 = await rotate(s);
        expect(r2.accepted, `second rotate must be accepted: ${r2.error}`).toBe(true);
        expect(r2.continuation!.endsWith('6a' + STATE2)).toBe(true);
      }, 120_000);

      const PRE_FIX: { label: string; state: Record<string, unknown> }[] = [
        // What the pre-fix TS codec wrote for an 8-byte hex value: `08 <word>`.
        { label: 'framed 8-byte words (08 <word>)', state: { oracleKey: '563412eeffc0ad0b', lastSig: '2a00000000000080', count: 4n } },
        // What the pre-fix Python / Ruby / Zig codecs wrote for an integer: OP_0.
        { label: 'empty pushes (00), the pre-fix Python/Ruby/Zig bytes', state: { oracleKey: '', lastSig: '', count: 4n } },
      ];
      for (const p of PRE_FIX) {
        it(`pre-fix layout — ${p.label} — REJECTED`, async () => {
          const s = await deploy(structuredClone(artifact));
          const r = await withPreFixCodec(s, () => rotate(s, p.state));
          expect(r.reachedEngine, `never reached Spend: ${r.error ?? '(accepted)'}`).toBe(true);
          expect(r.accepted).toBe(false);
        }, 120_000);
      }
    });
  }
}

describe('F-035 — the locking script all seven SDKs agree on (sdk-output state-rabin) is spendable', () => {
  it('TS SDK reproduces expected-locking.hex from input.json, and rotate on it is ACCEPTED', async () => {
    const dir = join(SDK_OUTPUT, 'tests', 'state-rabin');
    const input = JSON.parse(readFileSync(join(dir, 'input.json'), 'utf8')) as { artifact: RunarArtifact };
    const golden = readFileSync(join(dir, 'expected-locking.hex'), 'utf8').trim();
    expect(golden.endsWith('6a' + STATE0)).toBe(true);

    const s = await deploy(input.artifact);
    expect(s.prevTx.outputs[0]!.lockingScript.toHex()).toBe(golden);
    // The sdk-output artifact is stripped of its ANF, so the SDK cannot derive
    // the post-state itself; hand it the hand-derived one.
    const r = await rotate(s, { oracleKey: NEXT_KEY, lastSig: NEXT_SIG, count: 4n });
    expect(r.accepted, `rotate on the seven-SDK locking script must be accepted: ${r.error}`).toBe(true);
    expect(r.continuation!.endsWith('6a' + STATE1)).toBe(true);
  }, 120_000);
});
