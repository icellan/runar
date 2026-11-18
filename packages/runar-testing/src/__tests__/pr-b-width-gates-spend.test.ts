/**
 * PR B (#213, #180) — execution proof, all seven tiers, both constant-folding
 * modes: a public method's fixed-width parameters are width-checked at entry.
 *
 * Rule (spec/type-system.md, "Fixed-width parameters"): every PUBLIC method
 * gates each parameter of type Point (64 bytes), P256Point (64), P384Point
 * (96), Sha256 (32), Ripemd160 (20) and Addr (20) with
 *
 *     <copy of param> OP_SIZE <width> OP_NUMEQUALVERIFY OP_DROP
 *
 * before any of the body runs. A PubKey parameter (33) gets the same gate
 * UNLESS its value only ever reaches checkSig / checkMultiSig / hash160, so a
 * plain P2PKH keeps its standard template bytes. Sig is never gated
 * (variable-width DER).
 *
 * #213: the compiler-injected `_changePKH` is a public Ripemd160 parameter of
 * every stateful method that commits a change output, so the same entry gate
 * covers it (exactly once). Before the fix a spender could pass
 *
 *     _changePKH = pkh || 88ac || le8(1) || 19 || extra[:-2]
 *
 * and the covenant's change output `amount || 19 76a914 <_changePKH> 88ac`
 * serialised as the honest change output FOLLOWED BY an extra 1-sat output
 * paying `extra`: hashOutputs then matched a transaction carrying an output
 * the covenant never authorised.
 *
 * #180: `Lock.lock(p: Point)` builds `40 <p> 87`. A 67-byte `p`
 * (SECRET || 6d5151) used to be accepted and created an output spendable by
 * any 64-byte push.
 *
 * Oracle: @bsv/sdk's production Spend with strict consensus flags
 * (`validateContractInput` and the SDK's `dryRun` replay of input 0). The
 * attack transactions are built by hand or with an "attacker SDK" (the SDK's
 * shared width table temporarily widened, see n045-state-fixed-width-spend);
 * the on-chain script is the only judge. Expected verdicts come from the
 * sources above, never from compiler output.
 *
 * Does NOT prove: the regtest node's verdict (see the integration suites), or
 * anything about a Sig parameter (deliberately ungated).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript, encodePushData } from 'runar-sdk';
import { STATE_FIELD_WIDTHS } from 'runar-ir-schema';
import { Hash, LockingScript, Transaction, UnlockingScript, Utils } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-prb-'));

// ---------------------------------------------------------------------------
// Contracts
// ---------------------------------------------------------------------------

/** #213: a stateful contract with addRawOutput (and so a change output). */
const RAW_SRC = `import { StatefulSmartContract } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class RawPay extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }

  public pay(scriptBytes: ByteString) {
    this.addRawOutput(1000n, scriptBytes);
    this.count = this.count + 1n;
    this.addOutput(100000n, this.count);
  }
}
`;

/**
 * #180 (c), from the issue, plus the addOutput that carries the state write
 * (D18 refuses a state write with only raw outputs).
 */
const LOCK_SRC = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { Point } from 'runar-lang';

class Lock extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }

  public lock(p: Point) {
    this.addRawOutput(1000n, cat(cat(toByteString('40'), p), toByteString('87')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
`;

/** D13: a PubKey that is NOT only verified — spliced into a P2PK output. */
const P2PK_SRC = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { PubKey } from 'runar-lang';

class PayToKey extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }

  public pay(pk: PubKey) {
    this.addRawOutput(1000n, cat(cat(toByteString('21'), pk), toByteString('ac')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
`;

/** D13 laundering probes: the key leaves an arm / a helper as a VALUE. */
const TERNARY_SRC = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { PubKey } from 'runar-lang';

class PickKey extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }

  public pay(pick: boolean, a: PubKey, b: PubKey) {
    const k = pick ? a : b;
    this.addRawOutput(1000n, cat(cat(toByteString('21'), k), toByteString('ac')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
`;

const HELPER_RET_SRC = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { PubKey } from 'runar-lang';

class IdKey extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }

  private id(k: PubKey): PubKey { return k; }

  public pay(pk: PubKey) {
    this.addRawOutput(1000n, cat(cat(toByteString('21'), this.id(pk)), toByteString('ac')));
    this.n = this.n + 1n;
    this.addOutput(100000n, this.n);
  }
}
`;

/** Branch-merged locals re-bind `nk` by name, so the alias walk can cycle. */
const MERGED_ALIAS_SRC = `import { StatefulSmartContract, assert } from 'runar-lang';
import type { PubKey } from 'runar-lang';

class MergedKey extends StatefulSmartContract {
  closed: bigint = 0n;
  k: PubKey = "${'00'.repeat(33)}" as PubKey;
  amt: bigint = 0n;
  constructor(seed: bigint) { super(seed); this.closed = seed; }

  public bid(bidderKey: PubKey, bidAmount: bigint) {
    assert(this.closed === 0n);
    let nk = this.k;
    let namt = this.amt;
    if (this.amt === 0n) { nk = bidderKey; namt = bidAmount; }
    else { nk = bidderKey; namt = bidAmount + 1n; }
    this.addOutput(bidAmount, this.closed, nk, namt);
  }
}
`;

const P2PKH_SRC = readFileSync(join(REPO, 'examples', 'ts', 'p2pkh', 'P2PKH.runar.ts'), 'utf8');
const P2PKH_GOLDEN = readFileSync(join(REPO, 'conformance', 'tests', 'basic-p2pkh', 'expected-script.hex'), 'utf8').trim();

// ---------------------------------------------------------------------------
// Tier plumbing (as in n045-state-fixed-width-spend.test.ts)
// ---------------------------------------------------------------------------

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

function artifactFor(tier: string, src: string, fileName: string, disableFold: boolean): RunarArtifact {
  if (tier === 'ts') {
    const r = compile(src, { fileName, disableConstantFolding: disableFold });
    if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
    return r.artifact as unknown as RunarArtifact;
  }
  const { cmd, pre, cwd } = NATIVE[tier]!();
  const fold = disableFold ? ['--disable-constant-folding'] : [];
  const p = writeTmp(fileName, src);
  if (tier === 'java') {
    const out = writeTmp('artifact.json', '');
    run(cmd, [...pre, '--source', p, '--emit-artifact', out, ...fold], cwd);
    return JSON.parse(readFileSync(out, 'utf8'));
  }
  return JSON.parse(run(cmd, [...pre, '--source', p, ...fold], cwd));
}

// RUNAR_PRB_TIERS=ts,go narrows the matrix while tiers are being built; the
// default (and CI) is all seven.
const TIERS = process.env.RUNAR_PRB_TIERS?.split(',') ?? ['ts', ...Object.keys(NATIVE)];

// ---------------------------------------------------------------------------
// Deploy / call
// ---------------------------------------------------------------------------

const ALICE = testKey('alice');
const MALLORY = testKey('bob');
const DEPLOY_SATS = 100_000;

interface Step { accepted: boolean; reachedEngine: boolean; error?: string; tx?: Transaction }
interface Session { provider: MockProvider; contract: RunarContract; prevTx: Transaction }

async function deploy(artifact: RunarArtifact, ctorArgs: unknown[]): Promise<Session> {
  const provider = new MockProvider();
  for (const k of [ALICE, MALLORY]) {
    const s = new LocalSigner(k.privKey);
    provider.addUtxo(await s.getAddress(), {
      txid: k.privKey.slice(0, 64),
      outputIndex: 0,
      satoshis: 5_000_000,
      script: buildP2PKHScript(k.pubKey),
    });
  }
  const contract = new RunarContract(artifact, ctorArgs);
  await contract.deploy(provider, new LocalSigner(ALICE.privKey), { satoshis: DEPLOY_SATS });
  const prevTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  return { provider, contract, prevTx };
}

async function call(s: Session, method: string, args: unknown[], who: { privKey: string }): Promise<Step> {
  const before = s.provider.getBroadcastedTxs().length;
  try {
    await s.contract.call(method, args, s.provider, new LocalSigner(who.privKey), {
      dryRun: true,
      satoshis: DEPLOY_SATS,
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
  return { accepted: validateContractInput(tx, 0, s.prevTx, 0), reachedEngine: true, tx };
}

/** The attacker's SDK: the shared width table believes `type` is `width` bytes. */
async function withWidth<T>(type: string, width: number, fn: () => Promise<T>): Promise<T> {
  const table = STATE_FIELD_WIDTHS as Record<string, { size: number; encoding: string }>;
  const original = table[type]!;
  table[type] = { size: width, encoding: original.encoding };
  try {
    return await fn();
  } finally {
    table[type] = original;
  }
}

// ---------------------------------------------------------------------------
// #213 attack transaction, built by hand from an honest call
// ---------------------------------------------------------------------------

function le8(n: number): string {
  let h = '';
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) { h += (v & 0xffn).toString(16).padStart(2, '0'); v >>= 8n; }
  return h;
}

function outputsHex(tx: Transaction): string {
  let h = '';
  for (const o of tx.outputs) {
    const s = o.lockingScript.toHex();
    h += le8(o.satoshis!) + Utils.toHex(new Utils.Writer().writeVarIntNum(s.length / 2).toArray()) + s;
  }
  return h;
}

function rebuildUnlock(hex: string, replace: Map<string, string>): string {
  const chunks = UnlockingScript.fromHex(hex).chunks;
  let out = '';
  for (const c of chunks) {
    if (c.data && c.data.length > 0) {
      const d = Utils.toHex(c.data);
      out += encodePushData(replace.get(d) ?? d);
    } else {
      out += c.op.toString(16).padStart(2, '0');
    }
  }
  return out;
}

/**
 * Re-witness the honest call `honest` with `_changePKH = pkh'` and the extra
 * output `extraScript` (1 sat) appended. `extraScript` must end in 88ac. With
 * `extraScript` undefined it re-witnesses the honest tx unchanged (harness
 * control: the surgery itself must not break an honest spend).
 */
function changePkhAttack(honest: Transaction, changePkh: string, extraScript?: string): Transaction {
  const tx = Transaction.fromHex(honest.toHex());
  let pkh2 = changePkh;
  if (extraScript !== undefined) {
    if (!extraScript.endsWith('88ac')) throw new Error('extra script must end in 88ac');
    const len = (extraScript.length / 2).toString(16).padStart(2, '0');
    pkh2 = changePkh + '88ac' + le8(1) + len + extraScript.slice(0, -4);
    tx.addOutput({ lockingScript: LockingScript.fromHex(extraScript), satoshis: 1 });
  }
  const unlockHex = tx.inputs[0]!.unlockingScript!.toHex();
  const pushes = UnlockingScript.fromHex(unlockHex).chunks.filter((c) => c.data && c.data.length > 0).map((c) => Utils.toHex(c.data!));
  // The preimage is the push whose hashOutputs field (bytes [-40, -8)) is the
  // honest tx's hashOutputs.
  const honestHashOutputs = Utils.toHex(Hash.hash256(Utils.toArray(outputsHex(honest), 'hex')));
  const preimage = pushes.find((p) => p.length > 80 && p.slice(-80, -16) === honestHashOutputs);
  if (!preimage) throw new Error('preimage push not found in the honest unlocking script');
  if (!pushes.includes(changePkh)) throw new Error('_changePKH push not found in the honest unlocking script');
  const newHashOutputs = Utils.toHex(Hash.hash256(Utils.toArray(outputsHex(tx), 'hex')));
  const preimage2 = preimage.slice(0, -80) + newHashOutputs + preimage.slice(-16);
  const replace = new Map([[changePkh, pkh2], [preimage, preimage2]]);
  tx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(rebuildUnlock(unlockHex, replace));
  return tx;
}

/** Spend's verdict on input 0 of `tx`; a script failure throws inside Spend. */
function verdict(tx: Transaction, prev: Transaction): { ok: boolean; error?: string } {
  try {
    return { ok: validateContractInput(tx, 0, prev, 0) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** Spend output `vout` of `src` with an unlocking script of one push. */
function spendWithPush(src: Transaction, vout: number, pushHex: string): boolean {
  const tx = new Transaction();
  tx.addInput({
    sourceTXID: src.id('hex'),
    sourceOutputIndex: vout,
    unlockingScript: UnlockingScript.fromHex(encodePushData(pushHex)),
    sequence: 0xffffffff,
  });
  tx.addOutput({ lockingScript: LockingScript.fromHex('6a'), satoshis: 0 });
  try {
    return validateContractInput(tx, 0, src, vout);
  } catch {
    return false; // Spend throws on a script failure
  }
}

// ---------------------------------------------------------------------------
// Execution tests
// ---------------------------------------------------------------------------

const ALICE_PKH = Utils.toHex(Hash.hash160(Utils.toArray(ALICE.pubKey, 'hex')));
const MALLORY_P2PKH = buildP2PKHScript(MALLORY.pubKey);
const SECRET = '11'.repeat(32) + '22'.repeat(32);
const WRONG64 = '33'.repeat(64);

for (const tier of TIERS) {
  for (const disableFold of [true, false]) {
    const tag = `[${tier}, fold ${disableFold ? 'off' : 'on'}]`;

    describe(`#213 ${tag} — _changePKH is width-checked`, () => {
      const artifact = artifactFor(tier, RAW_SRC, 'RawPay.runar.ts', disableFold);

      it('honest pay ACCEPTED, and the re-witnessed honest tx (harness control) ACCEPTED', async () => {
        const s = await deploy(artifact, [0n]);
        const u = await call(s, 'pay', ['51'], ALICE);
        expect(u.accepted, `honest pay must be accepted: ${u.error}`).toBe(true);
        const control = verdict(changePkhAttack(u.tx!, ALICE_PKH), s.prevTx);
        expect(control.ok, `harness control: ${control.error}`).toBe(true);
      }, 120_000);

      it('ATTACK: _changePKH = pkh||88ac||le8(1)||19||extra[:-2] appends an output -> REJECTED', async () => {
        const s = await deploy(artifact, [0n]);
        const u = await call(s, 'pay', ['51'], ALICE);
        expect(u.accepted, `honest pay must be accepted: ${u.error}`).toBe(true);
        const attack = changePkhAttack(u.tx!, ALICE_PKH, MALLORY_P2PKH);
        expect(attack.outputs.at(-1)!.lockingScript.toHex()).toBe(MALLORY_P2PKH);
        const v = verdict(attack, s.prevTx);
        expect(v.ok, 'an output the covenant never authorised was accepted').toBe(false);
        // Rejected by the width gate itself, not by some other check.
        expect(v.error).toMatch(/NUMEQUALVERIFY/);
      }, 120_000);
    });

    describe(`#180 ${tag} — Lock.lock(p: Point) is width-checked`, () => {
      const artifact = artifactFor(tier, LOCK_SRC, 'Lock.runar.ts', disableFold);

      it('honest 64-byte p ACCEPTED; the created output needs exactly p', async () => {
        const s = await deploy(artifact, [0n]);
        const u = await call(s, 'lock', [SECRET], ALICE);
        expect(u.accepted, `honest lock must be accepted: ${u.error}`).toBe(true);
        const vout = u.tx!.outputs.findIndex((o) => o.lockingScript.toHex() === '40' + SECRET + '87');
        expect(vout).toBeGreaterThanOrEqual(0);
        expect(spendWithPush(u.tx!, vout, WRONG64)).toBe(false);
        expect(spendWithPush(u.tx!, vout, SECRET)).toBe(true);
      }, 120_000);

      it('ATTACK: 67-byte p = SECRET||6d5151 -> lock REJECTED', async () => {
        const s = await deploy(artifact, [0n]);
        const p = SECRET + '6d5151';
        const u = await withWidth('Point', 67, () => call(s, 'lock', [p], MALLORY));
        let consequence = '';
        if (u.accepted) {
          const vout = u.tx!.outputs.findIndex((o) => o.lockingScript.toHex() === '40' + p + '87');
          consequence = ` — and its output is then spendable with a WRONG 64-byte push: ${spendWithPush(u.tx!, vout, WRONG64)}`;
        }
        expect(u.reachedEngine, `never reached Spend: ${u.error ?? '(accepted)'}${consequence}`).toBe(true);
        expect(u.accepted, `oversized Point accepted${consequence}`).toBe(false);
      }, 120_000);
    });

    describe(`D13 ${tag} — a PubKey spliced into an output is width-checked`, () => {
      const artifact = artifactFor(tier, P2PK_SRC, 'PayToKey.runar.ts', disableFold);

      it('honest 33-byte pk ACCEPTED', async () => {
        const s = await deploy(artifact, [0n]);
        const u = await call(s, 'pay', [MALLORY.pubKey], ALICE);
        expect(u.accepted, `honest pay must be accepted: ${u.error}`).toBe(true);
      }, 120_000);

      it('ATTACK: 36-byte pk = pk||6d5151 -> pay REJECTED', async () => {
        const s = await deploy(artifact, [0n]);
        const u = await withWidth('PubKey', 36, () => call(s, 'pay', [MALLORY.pubKey + '6d5151'], MALLORY));
        expect(u.reachedEngine, `never reached Spend: ${u.error ?? '(accepted)'}`).toBe(true);
        expect(u.accepted).toBe(false);
      }, 120_000);
    });

    describe(`D13 ${tag} — P2PKH keeps its standard template`, () => {
      const artifact = artifactFor(tier, P2PKH_SRC, 'P2PKH.runar.ts', disableFold);

      it('script bytes equal the basic-p2pkh golden (no gate on a verified-only PubKey)', () => {
        expect(artifact.script).toBe(P2PKH_GOLDEN);
      });

      it('honest P2PKH spend ACCEPTED', async () => {
        const s = await deploy(artifact, [ALICE_PKH]);
        const u = await call(s, 'unlock', [null, ALICE.pubKey], ALICE);
        expect(u.accepted, `honest unlock must be accepted: ${u.error}`).toBe(true);
      }, 120_000);
    });
  }
}

// ---------------------------------------------------------------------------
// Static pins: the gate bytes each tier emits
// ---------------------------------------------------------------------------

function hits(script: string, pattern: string): number {
  return [...script.matchAll(new RegExp(pattern, 'g'))].filter((m) => m.index! % 2 === 0).length;
}

describe('PR B — every tier emits the entry gate exactly once per gated parameter', () => {
  for (const tier of TIERS) {
    it(`[${tier}] Lock.lock: Point gate (depth 3) then _changePKH gate (depth 2), once each`, () => {
      const a = artifactFor(tier, LOCK_SRC, 'Lock.runar.ts', true);
      // params [p, _changePKH, _changeAmount, txPreimage] (no _newAmount: the
      // method has a raw output), txPreimage on top:
      // <3 OP_PICK> OP_SIZE 0x40 OP_NUMEQUALVERIFY OP_DROP, <2 OP_PICK> OP_SIZE 0x14 OP_NUMEQUALVERIFY OP_DROP
      expect(a.script).toContain('5379820140' + '9d75' + '5279820114' + '9d75');
      expect(hits(a.script, '8201409d')).toBe(1);
      expect(hits(a.script, '8201149d')).toBe(1);
    }, 120_000);

    it(`[${tier}] PayToKey.pay: a spliced PubKey gets OP_SIZE 0x21 OP_NUMEQUALVERIFY`, () => {
      const a = artifactFor(tier, P2PK_SRC, 'PayToKey.runar.ts', true);
      expect(a.script).toContain('5379820121' + '9d75');
      expect(hits(a.script, '8201219d')).toBe(1);
    }, 120_000);

    it(`[${tier}] a PubKey leaving a ternary arm or a private helper's return is gated (no laundering)`, () => {
      const t = artifactFor(tier, TERNARY_SRC, 'PickKey.runar.ts', true);
      expect(hits(t.script, '8201219d'), 'both arms\' keys').toBe(2);
      const h = artifactFor(tier, HELPER_RET_SRC, 'IdKey.runar.ts', true);
      expect(hits(h.script, '8201219d'), 'helper return').toBe(1);
    }, 120_000);

    it(`[${tier}] a cyclic merged-local alias terminates and gates the PubKey once`, () => {
      const a = artifactFor(tier, MERGED_ALIAS_SRC, 'MergedKey.runar.ts', true);
      // One entry gate on bidderKey (params [bidderKey, bidAmount, _changePKH,
      // _changeAmount, txPreimage]: depth 4 -> 54 79)
      // plus N-045's write check on the PubKey state field `k` = 2 checks.
      expect(a.script).toContain('5479820121' + '9d75');
      expect(hits(a.script, '8201219d')).toBe(2);
    }, 120_000);

    it(`[${tier}] RawPay.pay: _changePKH gated once`, () => {
      const a = artifactFor(tier, RAW_SRC, 'RawPay.runar.ts', true);
      expect(hits(a.script, '8201149d')).toBe(1);
    }, 120_000);
  }
});
