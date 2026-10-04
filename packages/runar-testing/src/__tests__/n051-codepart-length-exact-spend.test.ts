/**
 * N-051 (EXT-2 TaffyTail) — execution proof, all seven tiers, both
 * constant-folding modes: the stateful code-part authentication pins
 * `SIZE(_codePart)` EXACTLY, even when a readonly variable-length value (a
 * ByteString tag) makes the deployed code length unknown at compile time.
 *
 *     message: ByteString;            // mutable, variable-length state
 *     readonly tag: ByteString;       // 256 bytes, interior 0x6a at index 206
 *     readonly owner: PubKey;
 *     public burn(sig: Sig) { assert(checkSig(sig, this.owner)); }   // owner-only terminal
 *     public post(next: ByteString, claimedTag: ByteString) {        // anyone, value-preserving
 *       assert(claimedTag === this.tag);
 *       this.addOutput(extractAmount(this.txPreimage), next);
 *     }
 *
 * Before the fix the compiler could not size the baked `tag`, so it pinned
 * `SIZE(_codePart) >= <template length>` (OP_GREATERTHANOREQUAL). The only
 * other constraint on where the claimed code part ENDS is "the next scriptCode
 * byte is 0x6a" — and the 0x6a inside the baked tag satisfies it. A stranger
 * calling `post` supplies `_codePart = trueCode[:cut]` (cut = the tag's interior
 * 0x6a, still above the lower bound) and a continuation
 * `trueCode[:cut] || 6a || push(next)`, whose `next` bytes complete the cut
 * PUSHDATA and then run as script (`75`x8 `68` `51`). The successor's code is
 * attacker-chosen; a second spend pays the stranger.
 *
 * Since N-044 the state reader also requires the state section to be consumed
 * EXACTLY, so the bytes after the cut must parse as one `message` push ending at
 * the end of the script. The tag therefore carries `6a 4d LL LL` at the cut
 * (a PUSHDATA2 header inside an opaque readonly value), and the stranger first
 * makes an honest `post` that sets `message` to the length that makes
 * `LL LL` reach exactly to the end of the locking script. Nothing about that
 * needs the owner: `post` is open to anyone, and the tag is ordinary data.
 *
 * The fix (user decision R24, option (a)): the pin is always OP_NUMEQUAL, and
 * when its value is not known at compile time the compiler records the 4-byte
 * length field as an artifact `codePartLenSlots` entry that the deploying SDK
 * patches with the real deployed code-part length.
 *
 * Oracle: @bsv/sdk's production Spend with strict consensus flags (the SDK's
 * `dryRun` replay of input 0, and `validateContractInput` ->
 * `newConsensusSpend`) on each tier's own CLI artifact, DEPLOYED THROUGH THE TS
 * SDK — so the deploy-time patch is the thing under test, not a hand-built
 * script. Every expected verdict is derived by hand from the source above.
 *
 * What this proves: for each tier and folding mode, (a) the poisoned
 * continuation (truncated `_codePart` cut at the tag's interior 0x6a) is
 * REJECTED by the deployed contract's own script; (b) an honest
 * value-preserving `post` by a stranger is ACCEPTED and carries state, after
 * which the stranger's `burn` is rejected and the owner's is accepted; (c) the
 * artifact carries a `codePartLenSlots` entry and the deployed field equals the
 * deployed code-part length. What it does NOT prove: the six non-TS SDKs'
 * deploy splice (that is pinned byte-for-byte by the sdk-output conformance
 * cases `state-covenant` and `inscription-pin-lower-bound` and each SDK's own N-051 test); a dishonest
 * DEPLOYER, who chooses the code anyway.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript, encodePushData } from 'runar-sdk';
import { LockingScript, Transaction, UnlockingScript } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n051-'));

const SOURCE = `import { StatefulSmartContract, assert, extractAmount, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

class TaffyTailVault extends StatefulSmartContract {
  message: ByteString;
  readonly tag: ByteString;
  readonly owner: PubKey;

  constructor(message: ByteString, tag: ByteString, owner: PubKey) {
    super(message, tag, owner);
    this.message = message;
    this.tag = tag;
    this.owner = owner;
  }

  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }

  public post(next: ByteString, claimedTag: ByteString) {
    assert(claimedTag === this.tag);
    this.addOutput(extractAmount(this.txPreimage), next);
  }
}
`;
const FILE = 'TaffyTailVault.runar.ts';

/** The tag's interior 0x6a, the attacker's cut point. */
const TAG_CUT = 206;
/** 256 bytes: `42`x206 || 6a || 4d LL LL || `42`x46. */
const tagWith = (pushLen: number): string =>
  '42'.repeat(TAG_CUT) + '6a' + '4d' +
  (pushLen & 0xff).toString(16).padStart(2, '0') + ((pushLen >> 8) & 0xff).toString(16).padStart(2, '0') +
  '42'.repeat(46);
const MESSAGE0 = '6a0141';
/** The `message` the stranger sets before the attack: 100 bytes, framed `4c 64 ..`. */
const SHAPED_MESSAGE = '44'.repeat(100);
const OWNER = testKey('alice');
const STRANGER = testKey('bob');
const DEPLOY_SATS = 100_000;

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
    const r = compile(SOURCE, { fileName: FILE, disableConstantFolding: disableFold });
    if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
    return r.artifact as unknown as RunarArtifact;
  }
  const { cmd, pre, cwd } = NATIVE[tier]!();
  const fold = disableFold ? ['--disable-constant-folding'] : [];
  const p = writeTmp(FILE, SOURCE);
  if (tier === 'java') {
    const out = writeTmp('artifact.json', '');
    run(cmd, [...pre, '--source', p, '--emit-artifact', out, ...fold], cwd);
    return JSON.parse(readFileSync(out, 'utf8'));
  }
  return JSON.parse(run(cmd, [...pre, '--source', p, ...fold], cwd));
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
  tag: string;
}

/**
 * The tag whose `4d LL LL` (right after the cut) frames exactly the rest of the
 * locking script once `message` is SHAPED_MESSAGE: LL = lockLen - (cut + 4),
 * with lockLen = codeLen + 1 (OP_RETURN) + 2 + 100 (`4c 64 || message`).
 */
function tagFor(artifact: RunarArtifact): string {
  const probe = tagWith(0);
  const code = new RunarContract(artifact, [MESSAGE0, probe, OWNER.pubKey]).getCodePartHex();
  const cut = code.indexOf(probe) / 2 + TAG_CUT;
  const lockLen = code.length / 2 + 1 + 2 + SHAPED_MESSAGE.length / 2;
  return tagWith(lockLen - (cut + 4));
}

async function deploy(artifact: RunarArtifact): Promise<Session> {
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
  const tag = tagFor(artifact);
  const contract = new RunarContract(artifact, [MESSAGE0, tag, OWNER.pubKey]);
  await contract.deploy(provider, new LocalSigner(OWNER.privKey), { satoshis: DEPLOY_SATS });
  const prevTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  return { provider, contract, prevTx, tag };
}

function rejection(e: unknown): Step {
  const error = e instanceof Error ? e.message : String(e);
  return {
    accepted: false,
    reachedEngine: error.includes('local pre-broadcast dry-run rejected the primary contract input'),
    error: error.slice(0, 400),
  };
}

async function call(s: Session, method: string, args: unknown[], who: { privKey: string }, extra: Record<string, unknown> = {}): Promise<Step> {
  const before = s.provider.getBroadcastedTxs().length;
  try {
    await s.contract.call(method, args, s.provider, new LocalSigner(who.privKey), {
      dryRun: true,
      satoshis: DEPLOY_SATS,
      ...extra,
    });
  } catch (e) {
    return rejection(e);
  }
  const tx = Transaction.fromHex(s.provider.getBroadcastedTxs()[before]!);
  const accepted = validateContractInput(tx, 0, s.prevTx, 0);
  s.prevTx = tx;
  return { accepted, reachedEngine: true };
}

const invalidate = (tx: Transaction): void => {
  const t = tx as unknown as Record<string, unknown>;
  t.hexCache = undefined;
  t.rawBytesCache = undefined;
  t.cachedHash = undefined;
};

/**
 * The attacker's spend (TaffyTail step 1): a value-preserving `post` whose
 * continuation is `trueCode[:cut] || 6a || push(next)`, with `_codePart`
 * claimed as `trueCode[:cut]`. Built from the SDK's own prepared call, then
 * rewritten exactly as a hand-built transaction would be: the continuation
 * output is replaced, the stranger's fee input is re-signed, the OP_PUSH_TX
 * preimage is recomputed, and the claimed code part is what the unlocking
 * script pushes. Only the on-chain script judges it.
 */
async function poisonedPost(s: Session): Promise<Step & { trueLen: number; claimedLen: number; tx?: Transaction }> {
  const next = '42'.repeat(48) + '75'.repeat(8) + '6851';
  const stranger = new LocalSigner(STRANGER.privKey);
  s.contract.connect(s.provider, stranger);
  const first = await s.contract.prepareCall('post', [next, s.tag], {
    satoshis: DEPLOY_SATS,
    newState: { message: next },
    dryRun: true,
  });
  const trueCode = s.contract.getCodePartHex();
  const cut = trueCode.indexOf(s.tag) / 2 + TAG_CUT;
  if (trueCode.slice(cut * 2, cut * 2 + 2) !== '6a') throw new Error('test setup: cut is not at the tag\'s 0x6a');
  const claimedCode = trueCode.slice(0, cut * 2);
  const poisonedScript = claimedCode + '6a' + encodePushData(next);
  first.tx.outputs[0]!.lockingScript = LockingScript.fromHex(poisonedScript);
  invalidate(first.tx);
  const fee = (await s.provider.getUtxos(await stranger.getAddress()))[0]!;
  const feeSig = await stranger.sign(first.tx.toHex(), 1, fee.script, fee.satoshis);
  first.tx.inputs[1]!.unlockingScript = UnlockingScript.fromHex(
    encodePushData(feeSig) + encodePushData(await stranger.getPublicKey()),
  );
  invalidate(first.tx);
  const prep = first as unknown as { preimage: string; _contractUtxo: { script: string; satoshis: number } };
  prep.preimage = s.contract.computeOpPushTxWithCodeSep(
    first.tx, 0, prep._contractUtxo.script, prep._contractUtxo.satoshis, 1,
  ).preimageHex;
  // The unlocking script's `_codePart` push is whatever getCodePartHex returns.
  const c = s.contract as unknown as { getCodePartHex: () => string };
  const original = c.getCodePartHex;
  c.getCodePartHex = () => claimedCode;
  const lens = { trueLen: trueCode.length / 2, claimedLen: claimedCode.length / 2 };
  const before = s.provider.getBroadcastedTxs().length;
  try {
    await s.contract.finalizeCall(first, {});
  } catch (e) {
    return { ...rejection(e), ...lens };
  } finally {
    c.getCodePartHex = original;
  }
  const tx = Transaction.fromHex(s.provider.getBroadcastedTxs()[before]!);
  return { accepted: validateContractInput(tx, 0, s.prevTx, 0), reachedEngine: true, ...lens, tx };
}

/** Every `76 04 LL LL LL LL 81 (9c|a2) 69` pin in a script (byte-aligned). */
function decodePins(hex: string): { valueOffset: number; value: number; op: string }[] {
  const out: { valueOffset: number; value: number; op: string }[] = [];
  for (let i = 0; i + 18 <= hex.length; i += 2) {
    const seqHex = hex.slice(i, i + 18);
    if (!seqHex.startsWith('7604') || seqHex.slice(12, 14) !== '81' || seqHex.slice(16, 18) !== '69') continue;
    const op = seqHex.slice(14, 16);
    if (op !== '9c' && op !== 'a2') continue;
    const value = parseInt(seqHex.slice(4, 12).match(/../g)!.reverse().join(''), 16);
    out.push({ valueOffset: i / 2 + 2, value, op });
  }
  return out;
}

const TIERS = ['ts', ...Object.keys(NATIVE)];

for (const tier of TIERS) {
  for (const disableFold of [true, false]) {
    describe(`N-051 [${tier}, fold ${disableFold ? 'off' : 'on'}] — the code-part length pin is exact at deploy time`, () => {
      const artifact = artifactFor(tier, disableFold);

      it('the deployed pin is an equality on the deployed code-part length, patched through codePartLenSlots', () => {
        const slots = (artifact as unknown as { codePartLenSlots?: { byteOffset: number }[] }).codePartLenSlots;
        expect(slots, 'artifact carries no codePartLenSlots').toBeDefined();
        const templatePins = decodePins(artifact.script);
        expect(templatePins.length).toBeGreaterThan(0);
        expect(slots!.map((x) => x.byteOffset).sort((a, b) => a - b))
          .toEqual(templatePins.map((p) => p.valueOffset).sort((a, b) => a - b));
        const code = new RunarContract(artifact, [MESSAGE0, tagFor(artifact), OWNER.pubKey]).getCodePartHex();
        const deployedPins = decodePins(code);
        expect(deployedPins.length).toBe(templatePins.length);
        for (const p of deployedPins) {
          expect(p.op, 'pin must be OP_NUMEQUAL, never a lower bound').toBe('9c');
          expect(p.value).toBe(code.length / 2);
        }
      }, 120_000);

      it('ATTACK (TaffyTail step 1): _codePart cut at the tag\'s interior 0x6a -> poisoned post REJECTED', async () => {
        const s = await deploy(artifact);
        // The stranger shapes `message` first (an honest post, accepted before
        // and after the fix) so the bytes after the cut parse as exactly one push.
        const shape = await call(s, 'post', [SHAPED_MESSAGE, s.tag], STRANGER, { newState: { message: SHAPED_MESSAGE } });
        expect(shape.accepted, `shaping post must be accepted: ${shape.error}`).toBe(true);
        const r = await poisonedPost(s);
        expect(r.claimedLen).toBeLessThan(r.trueLen);
        expect(r.reachedEngine, `never reached Spend: ${r.error ?? '(accepted)'}`).toBe(true);
        expect(
          r.accepted,
          `poisoned continuation committed (true code ${r.trueLen} B, claimed ${r.claimedLen} B)`,
        ).toBe(false);
      }, 120_000);

      it('honest value-preserving post ACCEPTED; then stranger burn REJECTED, owner burn ACCEPTED', async () => {
        const s = await deploy(artifact);
        const next = '43'.repeat(300);
        const p = await call(s, 'post', [next, s.tag], STRANGER, { newState: { message: next } });
        expect(p.accepted, `honest post must be accepted: ${p.error}`).toBe(true);
        expect(s.contract.state).toEqual({ message: next });

        const terminal = (k: { pubKey: string }) => ({
          terminalOutputs: [{ scriptHex: buildP2PKHScript(k.pubKey), satoshis: DEPLOY_SATS - 1_000 }],
        });
        const sb = await call(s, 'burn', [null], STRANGER, terminal(STRANGER));
        expect(sb.reachedEngine, `never reached Spend: ${sb.error ?? '(accepted)'}`).toBe(true);
        expect(sb.accepted).toBe(false);

        const ob = await call(s, 'burn', [null], OWNER, terminal(OWNER));
        expect(ob.accepted, `owner's burn must be accepted: ${ob.error}`).toBe(true);
      }, 120_000);
    });
  }
}
