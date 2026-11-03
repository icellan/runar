/**
 * N-044 (+ F-083 / F-194 / F-361) — execution proof, all seven tiers, both
 * constant-folding modes: the on-chain state reader decodes a PUSHDATA length
 * as the UNSIGNED integer the writer meant.
 *
 *     memo: ByteString;  owner: PubKey;  balance: bigint;
 *     public annotate(nextMemo: ByteString) { this.memo = nextMemo; }   // anyone
 *     public withdraw(sig: Sig) { assert(checkSig(sig, this.owner)); }
 *
 * The writer frames a ByteString state field as `<len>`, `4c <len8>` or
 * `4d <len16 LE>` with an unsigned length. Before the fix every tier's reader
 * ran bare OP_BIN2NUM on those length bytes, which treats the top bit as a
 * SIGN bit:
 *   - `4c 80` (128 bytes) and `4d 00 80` (32768 bytes) read as length 0
 *     (negative zero). The memo reads as empty, and the next 33 bytes of the
 *     memo become `owner`. A stranger who annotates a memo that starts with
 *     their own pubkey can then withdraw.
 *   - `4c 81..ff` and a `4d` length with high byte >= 0x80 read negative, and
 *     OP_SPLIT aborts: the UTXO is bricked for the real owner too.
 *   - A length >= 65536 was silently framed as `4d <len mod 65536>` (no
 *     PUSHDATA4 arm in the writer or the reader).
 * The fix appends a 0x00 sign byte before OP_BIN2NUM for the header byte and
 * for the 1-, 2- and 4-byte lengths, accepts only the header bytes <76, 0x4c,
 * 0x4d and 0x4e (refusing anything else), adds PUSHDATA4 to the writer, and
 * requires the state section to be consumed exactly by the last field.
 *
 * Oracle: @bsv/sdk's production Spend with strict consensus flags
 * (`validateContractInput` -> `newConsensusSpend`), on each tier's own CLI
 * artifact deployed and called through the TS SDK. Every expected verdict and
 * state is derived BY HAND from the source above, never from compiler output.
 *
 * What this proves: for each of the seven tiers and both folding modes, the
 * compiled covenant (a) rejects the stranger's withdraw after the stranger set
 * a 128- or 32768-byte memo beginning with their pubkey, (b) accepts the
 * owner's withdraw and carries memo/owner/balance through unchanged at every
 * PUSHDATA boundary 0/75/76/127/128/129/255/256/32767/32768/65535/65536, so the
 * on-chain writer (annotate's continuation) and reader (withdraw's
 * deserialization) agree with the SDK at each of them, (c) refuses a state
 * header byte outside {<76, 0x4c, 0x4d, 0x4e} while accepting a well-formed
 * (non-minimal) 0x4e frame, and (d) refuses a state section with a trailing
 * byte after the last field.
 * What it does NOT prove: anything about lengths above 65536 (the 4-byte arm is
 * exercised only at 65536), or about the SDKs of the other six tiers — their
 * serializers are pinned against these frames by each SDK's own boundary test.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript, findLastOpReturn } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n044-'));

const SRC = `import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

class AnnotatedVault extends StatefulSmartContract {
  memo: ByteString;
  owner: PubKey;
  balance: bigint;

  constructor(memo: ByteString, owner: PubKey, balance: bigint) {
    super(memo, owner, balance);
    this.memo = memo;
    this.owner = owner;
    this.balance = balance;
  }

  public annotate(nextMemo: ByteString) {
    this.memo = nextMemo;
  }

  public withdraw(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }
}
`;
const FILE = 'AnnotatedVault.runar.ts';

const OWNER = testKey('alice');
const STRANGER = testKey('bob');
const BALANCE = 1000n;

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
  const src = writeTmp(FILE, SRC);
  if (tier === 'java') {
    const out = writeTmp('artifact.json', '');
    run(cmd, [...pre, '--source', src, '--emit-artifact', out, ...fold], cwd);
    return JSON.parse(readFileSync(out, 'utf8'));
  }
  return JSON.parse(run(cmd, [...pre, '--source', src, ...fold], cwd));
}

/** A memo of `len` bytes that begins with the stranger's pubkey (when it fits). */
function memoOf(len: number): string {
  if (len < 33) return 'ee'.repeat(len);
  return STRANGER.pubKey + '00'.repeat(len - 33);
}

interface Step {
  accepted: boolean;
  reachedEngine: boolean;
  error?: string;
}

interface Session {
  provider: MockProvider;
  contract: RunarContract;
  prevTx: Transaction;
}

async function fundedProvider(): Promise<MockProvider> {
  const provider = new MockProvider();
  for (const k of [OWNER, STRANGER]) {
    const s = new LocalSigner(k.privKey);
    provider.addUtxo(await s.getAddress(), {
      txid: k.privKey.slice(0, 64),
      outputIndex: 0,
      satoshis: 5_000_000,
      script: buildP2PKHScript(k.pubKey),
    });
  }
  return provider;
}

/**
 * Deploy with `memo`. When `lockingOverride` is given, the deploy output
 * carries that exact locking script instead of the SDK's own serialization —
 * the deployer's freedom to publish any state section, used to reach the
 * header-whitelist and exact-consumption checks.
 */
async function deploy(artifact: RunarArtifact, memo: string, lockingOverride?: (sdk: string) => string): Promise<Session> {
  const provider = await fundedProvider();
  const contract = new RunarContract(artifact, [memo, OWNER.pubKey, BALANCE]);
  if (lockingOverride) {
    const sdkScript = contract.getLockingScript();
    const crafted = lockingOverride(sdkScript);
    const own = contract.getLockingScript.bind(contract);
    let first = true;
    contract.getLockingScript = () => {
      if (first) { first = false; return crafted; }
      return own();
    };
  }
  await contract.deploy(provider, new LocalSigner(OWNER.privKey), {});
  const prevTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  return { provider, contract, prevTx };
}

async function call(s: Session, method: string, args: unknown[], who: { privKey: string }): Promise<Step> {
  const before = s.provider.getBroadcastedTxs().length;
  try {
    // dryRun: the SDK replays the contract input on the real Spend engine
    // before broadcast and throws a message unique to a script rejection.
    await s.contract.call(method, args, s.provider, new LocalSigner(who.privKey), { dryRun: true });
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
  return { accepted, reachedEngine: true };
}

const TIERS = ['ts', ...Object.keys(NATIVE)];
const OWNER_LENGTHS = [0, 75, 76, 127, 128, 129, 255, 256, 32767, 32768, 65535, 65536];
const ATTACK_LENGTHS = [128, 32768];

for (const tier of TIERS) {
  for (const disableFold of [true, false]) {
    describe(`N-044 [${tier}, fold ${disableFold ? 'off' : 'on'}] — PUSHDATA state lengths are unsigned`, () => {
      const artifact = artifactFor(tier, disableFold);

      for (const len of ATTACK_LENGTHS) {
        it(`ATTACK: stranger sets a ${len}-byte memo starting with their pubkey, then withdraws -> REJECTED`, async () => {
          const s = await deploy(artifact, '');
          const a = await call(s, 'annotate', [memoOf(len)], STRANGER);
          expect(a.accepted, `annotate must be accepted: ${a.error}`).toBe(true);
          const w = await call(s, 'withdraw', [null], STRANGER);
          expect(w.reachedEngine, `never reached Spend: ${w.error ?? '(accepted)'}`).toBe(true);
          expect(w.accepted, 'the stranger was read as `owner`').toBe(false);
        }, 120_000);
      }

      for (const len of OWNER_LENGTHS) {
        it(`owner withdraws after a stranger's ${len}-byte memo -> ACCEPTED, state carried through`, async () => {
          const s = await deploy(artifact, '');
          const a = await call(s, 'annotate', [memoOf(len)], STRANGER);
          expect(a.accepted, `annotate must be accepted: ${a.error}`).toBe(true);
          const w = await call(s, 'withdraw', [null], OWNER);
          expect(w.accepted, `owner's withdraw must be accepted: ${w.error}`).toBe(true);
          expect(s.contract.state).toEqual({ memo: memoOf(len), owner: OWNER.pubKey, balance: BALANCE });
        }, 120_000);
      }

      // The state section after OP_RETURN for memo = 'ab'.repeat(10):
      // <frame(memo)> || owner(33) || balance(8 LE).
      const MEMO10 = 'ab'.repeat(10);
      const tail = OWNER.pubKey + 'e803000000000000';
      const withState = (sdk: string, state: string) => sdk.slice(0, findLastOpReturn(sdk) + 2) + state;

      it('a well-formed 0x4e (PUSHDATA4) frame is read -> owner withdraw ACCEPTED', async () => {
        const s = await deploy(artifact, MEMO10, (sdk) => withState(sdk, '4e0a000000' + MEMO10 + tail));
        const w = await call(s, 'withdraw', [null], OWNER);
        expect(w.accepted, `0x4e frame must decode: ${w.error}`).toBe(true);
      }, 120_000);

      for (const header of ['4f', '51', '80', 'ff']) {
        it(`a state header byte 0x${header} (not <76, 0x4c, 0x4d, 0x4e) is REFUSED`, async () => {
          // `0a` after the header keeps a mis-parse as any accepted form in range.
          const s = await deploy(artifact, MEMO10, (sdk) => withState(sdk, header + '0a' + MEMO10 + tail));
          const w = await call(s, 'withdraw', [null], OWNER);
          expect(w.reachedEngine, `never reached Spend: ${w.error ?? '(accepted)'}`).toBe(true);
          expect(w.accepted).toBe(false);
        }, 120_000);
      }

      it('a trailing byte after the last state field is REFUSED (exact consumption)', async () => {
        const s = await deploy(artifact, MEMO10, (sdk) => withState(sdk, '0a' + MEMO10 + tail + '00'));
        const w = await call(s, 'withdraw', [null], OWNER);
        expect(w.reachedEngine, `never reached Spend: ${w.error ?? '(accepted)'}`).toBe(true);
        expect(w.accepted).toBe(false);
      }, 120_000);

      it('control: the same hand-built state without the trailing byte is ACCEPTED', async () => {
        const s = await deploy(artifact, MEMO10, (sdk) => withState(sdk, '0a' + MEMO10 + tail));
        const w = await call(s, 'withdraw', [null], OWNER);
        expect(w.accepted, w.error).toBe(true);
      }, 120_000);
    });
  }
}
