/**
 * @bsv/sdk Spend execution for the six fixtures the SDK-driven real-crypto
 * oracle cannot drive (coverage-ledger: harness gaps). Each test compiles the
 * fixture's .runar.ts, requires the artifact script to equal the committed
 * fold-OFF golden (so the bytes executed ARE the golden, with constructor args
 * spliced at its constructorSlots), hand-builds the spending transaction the
 * covenant expects, and runs it through `newConsensusSpend` (nVersion 1, the
 * strict rule set). Every fixture has a genuine accept and a tampered reject.
 *
 * Mirrors the go-sdk interpreter tests in conformance/script_execution_test.go
 * (add-raw-output, intent-prev-output-script, stateful-wots-gate) and adds
 * all-readonly-cleanstack, covenant-vault and intent-output-p2pkh.
 *
 * Added for the C=1 Any-S binding (ports #170), which moved all six goldens.
 * Does not prove: anything about a live node, or spend shapes other than the
 * ones built here.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Hash, LockingScript, PrivateKey, TransactionSignature, UnlockingScript, Utils,
} from '@bsv/sdk';
import { compile } from '../../packages/runar-compiler/src/index.js';
import { RunarContract } from '../../packages/runar-sdk/src/contract.js';
import { newConsensusSpend } from '../../packages/runar-testing/src/consensus-spend.js';
import { wotsKeygen, wotsSign } from '../../packages/runar-testing/src/crypto/wots.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TESTS = join(__dirname, '..', 'tests');
const SCOPE = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;
const PRIV = PrivateKey.fromHex('0000000000000000000000000000000000000000000000000000000000000007');
const PUB = PRIV.toPublicKey().toString();
const TXID_A = 'aa'.repeat(32);
const TXID_B = 'bb'.repeat(32);

const hex = (b: number[] | Uint8Array) => Utils.toHex(Array.from(b));
function push(h: string): string {
  const n = h.length / 2;
  if (n === 0) return '00';
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + h;
  if (n <= 0xff) return '4c' + n.toString(16).padStart(2, '0') + h;
  if (n <= 0xffff) return '4d' + hex([n & 0xff, n >> 8]) + h;
  return '4e' + hex([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, n >>> 24]) + h;
}
function pushInt(v: number): string {
  if (v === 0) return '00';
  if (v >= 1 && v <= 16) return (0x50 + v).toString(16);
  const out: number[] = [];
  let x = v;
  while (x > 0) { out.push(x & 0xff); x = Math.floor(x / 256); }
  if (out[out.length - 1]! & 0x80) out.push(0);
  return push(hex(out));
}
const p2pkh = (pkh: string) => `76a914${pkh}88ac`;
const le64 = (v: number) => { const b: number[] = []; let x = BigInt(v); for (let i = 0; i < 8; i++) { b.push(Number(x & 0xffn)); x >>= 8n; } return hex(b); };
const varint = (n: number) => (n < 0xfd ? n.toString(16).padStart(2, '0') : 'fd' + hex([n & 0xff, n >> 8]));
const serialiseOutputs = (outs: Out[]) => outs.map((o) => le64(o.satoshis) + varint(o.script.length / 2) + o.script).join('');

interface Out { satoshis: number; script: string }
interface Other { txid: string; vout: number; satoshis: number; script: string }

/** Compile the fixture and require artifact.script === committed golden. */
function artifactFor(fixture: string) {
  const cfg = JSON.parse(readFileSync(join(TESTS, fixture, 'source.json'), 'utf8'));
  const src = resolve(TESTS, fixture, cfg.sources['.runar.ts']);
  const r = compile(readFileSync(src, 'utf8'), { fileName: src.split('/').pop()!, disableConstantFolding: true });
  expect(r.success, (r.diagnostics ?? []).map((d) => d.message).join('\n')).toBe(true);
  const golden = readFileSync(join(TESTS, fixture, 'expected-script.hex'), 'utf8').trim();
  expect(r.artifact!.script, `${fixture}: compiled script is not the committed golden`).toBe(golden);
  return r.artifact!;
}

interface SpendCase {
  lockingHex: string;
  /** BIP-143 scriptCode (bytes after the executed OP_CODESEPARATOR). */
  scriptCodeHex: string;
  satoshis: number;
  outputs: Out[];
  /** inputs before the contract input (the contract input index = others.length). */
  others?: Other[];
  unlock: (preimageHex: string, sigFor: (subscriptHex: string) => string) => string;
}

function run(c: SpendCase): { ok: boolean; err?: string } {
  const others = c.others ?? [];
  const ctx = {
    sourceTXID: TXID_A, sourceOutputIndex: 0, sourceSatoshis: c.satoshis,
    transactionVersion: 1,
    otherInputs: others.map((o) => ({
      sourceTXID: o.txid, sourceOutputIndex: o.vout, sequence: 0xffffffff,
      sourceTransaction: undefined,
      unlockingScript: new UnlockingScript(),
    })) as never[],
    outputs: c.outputs.map((o) => ({ satoshis: o.satoshis, lockingScript: LockingScript.fromHex(o.script) })) as never[],
    inputIndex: others.length, inputSequence: 0xffffffff, lockTime: 0,
  };
  const preimageFor = (sub: string) => hex(TransactionSignature.formatBytes({
    ...ctx, subscript: LockingScript.fromHex(sub), scope: SCOPE,
  } as never) as unknown as number[]);
  const sigFor = (sub: string) =>
    (PRIV.sign(Hash.sha256(Utils.toArray(preimageFor(sub), 'hex'))).toDER('hex') as string) + '41';
  const unlocking = c.unlock(preimageFor(c.scriptCodeHex), sigFor);
  const spend = newConsensusSpend({
    ...ctx,
    lockingScript: LockingScript.fromHex(c.lockingHex),
    unlockingScript: UnlockingScript.fromHex(unlocking),
  } as never);
  try { return { ok: spend.validate() }; } catch (e) { return { ok: false, err: (e as Error).message }; }
}

/** scriptCode after the single OP_CODESEPARATOR at artifact.codeSeparatorIndex. */
function scriptCodeOf(lockingHex: string, csi: number): string {
  expect(lockingHex.slice(csi * 2, csi * 2 + 2)).toBe('ab');
  return lockingHex.slice((csi + 1) * 2);
}

describe('harness-gap fixtures execute on @bsv/sdk Spend (nVersion 1)', () => {
  it('add-raw-output: [raw, continuation, change] accepts; dropping the raw output rejects', () => {
    const a = artifactFor('add-raw-output');
    const c0 = new RunarContract(a, [0n]);
    const lock = c0.getLockingScript();
    const code = c0.getCodePartHex();
    const cont = new RunarContract(a, [1n]).getLockingScript();
    const raw = '6a0548656c6c6f';
    const changePKH = '00'.repeat(20);
    const outs = [{ satoshis: 1000, script: raw }, { satoshis: 0, script: cont }, { satoshis: 8500, script: p2pkh(changePKH) }];
    const unlock = (pre: string) => push(code) + push(raw) + push(changePKH) + pushInt(8500) + push(pre);
    const base = { lockingHex: lock, scriptCodeHex: scriptCodeOf(lock, a.codeSeparatorIndex!), satoshis: 10000, unlock };
    const ok = run({ ...base, outputs: outs });
    expect(ok.err).toBeUndefined();
    expect(ok.ok).toBe(true);
    expect(run({ ...base, outputs: outs.slice(1) }).ok).toBe(false);
  });

  it('all-readonly-cleanstack: owner signature accepts; another key rejects', () => {
    const a = artifactFor('all-readonly-cleanstack');
    const lock = new RunarContract(a, [PUB]).getLockingScript();
    const sc = scriptCodeOf(lock, a.codeSeparatorIndex!);
    const outs = [{ satoshis: 9000, script: p2pkh('11'.repeat(20)) }];
    const ok = run({ lockingHex: lock, scriptCodeHex: sc, satoshis: 10000, outputs: outs,
      unlock: (pre, sig) => push(sig(sc)) + push(pre) });
    expect(ok.err).toBeUndefined();
    expect(ok.ok).toBe(true);
    const other = new RunarContract(a, [PrivateKey.fromHex('09'.padStart(64, '0')).toPublicKey().toString()]).getLockingScript();
    expect(run({ lockingHex: other, scriptCodeHex: scriptCodeOf(other, a.codeSeparatorIndex!), satoshis: 10000, outputs: outs,
      unlock: (pre, sig) => push(sig(scriptCodeOf(other, a.codeSeparatorIndex!))) + push(pre) }).ok).toBe(false);
  });

  it('covenant-vault: paying minAmount to the recipient accepts; paying 1 sat less rejects', () => {
    const a = artifactFor('covenant-vault');
    const recipient = '22'.repeat(20);
    const lock = new RunarContract(a, [PUB, recipient, 5000n]).getLockingScript();
    // The owner pubkey slot (byte 1) sits before the method's separator, so in
    // the deployed script the separator moves by the push's growth (34 - 1).
    expect(a.constructorSlots![0]!.byteOffset).toBe(1);
    const sc = scriptCodeOf(lock, a.codeSeparatorIndex! + push(PUB).length / 2 - 1);
    // checkSig runs before the method's OP_CODESEPARATOR: its scriptCode is the whole script.
    const unlock = (pre: string, sig: (s: string) => string) => push(sig(lock)) + push(pre);
    const ok = run({ lockingHex: lock, scriptCodeHex: sc, satoshis: 10000,
      outputs: [{ satoshis: 5000, script: p2pkh(recipient) }], unlock });
    expect(ok.err).toBeUndefined();
    expect(ok.ok).toBe(true);
    expect(run({ lockingHex: lock, scriptCodeHex: sc, satoshis: 10000,
      outputs: [{ satoshis: 4999, script: p2pkh(recipient) }], unlock }).ok).toBe(false);
  });

  it('intent-output-p2pkh: output 0 = bond P2PKH accepts; a short bond rejects', () => {
    const a = artifactFor('intent-output-p2pkh');
    const bondPKH = '00112233445566778899aabbccddeeff00112233';
    const c = new RunarContract(a, [bondPKH, 5000n, 0n]);
    const lock = c.getLockingScript();
    const sc = scriptCodeOf(lock, a.codeSeparatorIndex!);
    const spend = (bond: number) => {
      const outs = [{ satoshis: bond, script: p2pkh(bondPKH) }, { satoshis: 4000, script: p2pkh('33'.repeat(20)) }];
      return run({ lockingHex: lock, scriptCodeHex: sc, satoshis: 10000, outputs: outs,
        unlock: (pre) => push(pre) + push(serialiseOutputs(outs)) });
    };
    const ok = spend(5000);
    expect(ok.err).toBeUndefined();
    expect(ok.ok).toBe(true);
    expect(spend(4999).ok).toBe(false);
  });

  it('intent-prev-output-script: the committed companion script accepts; a forged one rejects', () => {
    const a = artifactFor('intent-prev-output-script');
    const companion = p2pkh('11'.repeat(20));
    const expectedHash = hex(Hash.hash256(Utils.toArray(companion, 'hex')));
    const c0 = new RunarContract(a, [expectedHash, 0n]);
    const lock = c0.getLockingScript();
    const code = c0.getCodePartHex();
    const cont = new RunarContract(a, [expectedHash, 1n]).getLockingScript();
    const sc = scriptCodeOf(lock, a.codeSeparatorIndex!);
    const changePKH = '00'.repeat(20);
    const outs = [{ satoshis: 10000, script: cont }, { satoshis: 500, script: p2pkh(changePKH) }];
    const others = [{ txid: TXID_B, vout: 1, satoshis: 1000, script: companion }];
    const spend = (witness: string) => run({ lockingHex: lock, scriptCodeHex: sc, satoshis: 10000, outputs: outs, others,
      unlock: (pre) => push(code) + push(changePKH) + pushInt(500) + pushInt(10000) + push(pre) + push(witness) });
    const ok = spend(companion);
    expect(ok.err).toBeUndefined();
    expect(ok.ok).toBe(true);
    expect(spend(p2pkh('12'.repeat(20))).ok).toBe(false);
  });

  it('stateful-wots-gate: a real WOTS+ signature accepts; a tampered one rejects', () => {
    const a = artifactFor('stateful-wots-gate');
    const c0 = new RunarContract(a, [0n]);
    const lock = c0.getLockingScript();
    const code = c0.getCodePartHex();
    const cont = new RunarContract(a, [1n]).getLockingScript();
    const sc = scriptCodeOf(lock, a.codeSeparatorIndex!);
    const kp = wotsKeygen(new Uint8Array(32).fill(5), new Uint8Array(32).fill(6));
    const msg = Utils.toArray('advance the stateful WOTS+ gate', 'utf8');
    const sig = wotsSign(Uint8Array.from(msg), kp.sk, kp.pk.slice(0, 32));
    const changePKH = '00'.repeat(20);
    const outs = [{ satoshis: 10000, script: cont }, { satoshis: 500, script: p2pkh(changePKH) }];
    const spend = (s: Uint8Array) => run({ lockingHex: lock, scriptCodeHex: sc, satoshis: 10000, outputs: outs,
      unlock: (pre) => push(code) + push(hex(msg)) + push(hex(s)) + push(hex(kp.pk)) + push(changePKH)
        + pushInt(500) + pushInt(10000) + push(pre) });
    const ok = spend(sig);
    expect(ok.err).toBeUndefined();
    expect(ok.ok).toBe(true);
    const bad = Uint8Array.from(sig); bad[0] ^= 1;
    expect(spend(bad).ok).toBe(false);
  });
});
