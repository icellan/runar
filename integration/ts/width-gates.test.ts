/**
 * PR B (#213, #180) regtest — one on-chain negative per entry-gate kind.
 *
 * Every public method width-checks its fixed-width parameters at entry
 * (`<copy> OP_SIZE <w> OP_NUMEQUALVERIFY OP_DROP`), the compiler-injected
 * `_changePKH` included; a PubKey is checked unless it only reaches
 * checkSig / checkMultiSig / hash160 (spec/type-system.md §2.2).
 *
 *   - Point (#180): `Lock.lock(SECRET || 6d5151)` (67 bytes), built by an
 *     "attacker SDK" whose width table believes a Point is 67 bytes, is
 *     refused by the node; the honest 64-byte call is mined.
 *   - PubKey spliced into an output (D13): a 36-byte key, same shape.
 *   - _changePKH (#213): the honest call is re-witnessed by hand with
 *     `_changePKH = pkh || 88ac || le8(1) || 19 || extra[:-2]`, a lowered
 *     `_changeAmount` (fee headroom) and the extra output appended; the funding
 *     inputs are re-signed. The node refuses it; the same surgery WITHOUT the
 *     extra output (control) is accepted, so the harness itself is sound.
 *
 * Proves: the node (not the SDK) refuses each attack with
 * mandatory-script-verify-flag-failed. Does not prove: other tiers' bytes on
 * chain (their bytes equal TS's, pinned by the conformance suite).
 */

import { describe, it, expect } from 'vitest';
import { Hash, LockingScript, P2PKH, PrivateKey, Transaction, UnlockingScript, Utils } from '@bsv/sdk';
import { RunarContract, encodePushData, encodeScriptNumber } from 'runar-sdk';
import { STATE_FIELD_WIDTHS } from 'runar-ir-schema';
import type { RPCProvider } from 'runar-sdk';
import { compileSource } from './helpers/compile.js';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider, expectNodeRejected, rpcCall, SCRIPT_VERIFY_FAILED } from './helpers/node.js';

const LOCK_SRC = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { Point } from 'runar-lang';

class Lock extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }

  public lock(p: Point) {
    this.addRawOutput(1000n, cat(cat(toByteString('40'), p), toByteString('87')));
    this.n = this.n + 1n;
    this.addOutput(50000n, this.n);
  }
}
`;

const P2PK_SRC = `import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { PubKey } from 'runar-lang';

class PayToKey extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }

  public pay(pk: PubKey) {
    this.addRawOutput(1000n, cat(cat(toByteString('21'), pk), toByteString('ac')));
    this.n = this.n + 1n;
    this.addOutput(50000n, this.n);
  }
}
`;

const RAW_SRC = `import { StatefulSmartContract } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class RawPay extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }

  public pay(scriptBytes: ByteString) {
    this.addRawOutput(1000n, scriptBytes);
    this.count = this.count + 1n;
    this.addOutput(50000n, this.count);
  }
}
`;

const SECRET = '11'.repeat(32) + '22'.repeat(32);

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

describe('PR B entry width gates (regtest)', () => {
  it('Point (#180): honest 64-byte lock mined; 67-byte lock refused by the node', async () => {
    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);
    const contract = new RunarContract(compileSource(LOCK_SRC, 'Lock.runar.ts'), [0n]);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    await expectNodeRejected(
      provider,
      () => withWidth('Point', 67, () => contract.call('lock', [SECRET + '6d5151'], provider, signer)),
      SCRIPT_VERIFY_FAILED,
    );

    const { txid } = await contract.call('lock', [SECRET], provider, signer);
    expect(txid).toHaveLength(64);
    expect(contract.state.n).toBe(1n);
  });

  it('PubKey spliced into an output (D13): honest 33-byte pay mined; 36-byte pay refused by the node', async () => {
    const provider = createProvider();
    const { signer, pubKeyHex } = await createFundedWallet(provider);
    const contract = new RunarContract(compileSource(P2PK_SRC, 'PayToKey.runar.ts'), [0n]);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    await expectNodeRejected(
      provider,
      () => withWidth('PubKey', 36, () => contract.call('pay', [pubKeyHex + '6d5151'], provider, signer)),
      SCRIPT_VERIFY_FAILED,
    );

    const { txid } = await contract.call('pay', [pubKeyHex], provider, signer);
    expect(txid).toHaveLength(64);
  });

  it('_changePKH (#213): an appended output is refused by the node; the re-witnessed honest tx is accepted', async () => {
    const provider = createProvider();
    const wallet = await createFundedWallet(provider);
    const contract = new RunarContract(compileSource(RAW_SRC, 'RawPay.runar.ts'), [0n]);
    await contract.deploy(provider, wallet.signer, { satoshis: 50_000 });

    // Capture the honest call tx without broadcasting it.
    const honest = await captureCall(provider, () =>
      contract.call('pay', ['51'], provider, wallet.signer));

    const attack = await rewitness(honest, wallet, true);
    await expect(rpcCall('sendrawtransaction', attack.toHex())).rejects.toThrow(SCRIPT_VERIFY_FAILED);

    const control = await rewitness(honest, wallet, false);
    const txid = await rpcCall('sendrawtransaction', control.toHex());
    expect(txid).toBe(control.id('hex'));
  });
});

// ---------------------------------------------------------------------------
// #213 helpers
// ---------------------------------------------------------------------------

class Captured extends Error {
  constructor(readonly tx: Transaction) { super('captured'); }
}

async function captureCall(provider: RPCProvider, call: () => Promise<unknown>): Promise<Transaction> {
  const original = provider.broadcast.bind(provider);
  provider.broadcast = async (tx: Transaction) => { throw new Captured(Transaction.fromHex(tx.toHex())); };
  try {
    await call();
  } catch (e) {
    if (e instanceof Captured) return e.tx;
    throw e;
  } finally {
    provider.broadcast = original;
  }
  throw new Error('the call never reached broadcast');
}

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

const FEE_HEADROOM = 1000;

/**
 * Re-witness input 0 of `honest` with a lowered change amount (fee headroom
 * for the bigger tx) and, when `attack`, `_changePKH` extended so the change
 * output serialises as itself followed by a 1-sat P2PKH output to an address
 * of the attacker's choosing. Funding inputs are re-signed.
 */
async function rewitness(
  honest: Transaction,
  wallet: { privKeyHex: string; pubKeyHash: string },
  attack: boolean,
): Promise<Transaction> {
  const tx = Transaction.fromHex(honest.toHex());
  const pkh = wallet.pubKeyHash;
  const changeScript = '76a914' + pkh + '88ac';
  const changeIdx = tx.outputs.findIndex((o) => o.lockingScript.toHex() === changeScript);
  if (changeIdx !== tx.outputs.length - 1) throw new Error('change output is not last');
  const oldChange = tx.outputs[changeIdx]!.satoshis!;
  const newChange = oldChange - FEE_HEADROOM;
  tx.outputs[changeIdx]!.satoshis = newChange;

  let pkh2 = pkh;
  if (attack) {
    const extra = '76a914' + 'ab'.repeat(20) + '88ac';
    pkh2 = pkh + '88ac' + le8(1) + '19' + extra.slice(0, -4);
    tx.addOutput({ lockingScript: LockingScript.fromHex(extra), satoshis: 1 });
  }

  const chunks = tx.inputs[0]!.unlockingScript!.chunks;
  const honestHashOutputs = Utils.toHex(Hash.hash256(Utils.toArray(outputsHex(honest), 'hex')));
  const newHashOutputs = Utils.toHex(Hash.hash256(Utils.toArray(outputsHex(tx), 'hex')));
  const pkhIdx = chunks.findIndex((c) => c.data && Utils.toHex(c.data) === pkh);
  if (pkhIdx < 0) throw new Error('_changePKH push not found');
  let out = '';
  for (let i = 0; i < chunks.length; i++) {
    const c = chunks[i]!;
    const d = c.data && c.data.length > 0 ? Utils.toHex(c.data) : null;
    if (i === pkhIdx) out += encodePushData(pkh2);
    else if (i === pkhIdx + 1) out += encodeScriptNumber(BigInt(newChange));
    else if (d && d.length > 80 && d.slice(-80, -16) === honestHashOutputs) {
      out += encodePushData(d.slice(0, -80) + newHashOutputs + d.slice(-16));
    } else if (d) out += encodePushData(d);
    else out += c.op.toString(16).padStart(2, '0');
  }
  tx.inputs[0]!.unlockingScript = UnlockingScript.fromHex(out);

  const tmpl = new P2PKH().unlock(PrivateKey.fromHex(wallet.privKeyHex));
  for (let i = 1; i < tx.inputs.length; i++) {
    const inp = tx.inputs[i]!;
    inp.sourceTransaction = Transaction.fromHex((await rpcCall('getrawtransaction', inp.sourceTXID!)) as string);
    inp.unlockingScript = undefined;
  }
  for (let i = 1; i < tx.inputs.length; i++) {
    tx.inputs[i]!.unlockingScript = await tmpl.sign(tx, i);
  }
  return tx;
}
