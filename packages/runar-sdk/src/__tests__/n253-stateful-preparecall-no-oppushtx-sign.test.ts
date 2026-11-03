/**
 * N-253 (PERF, LOW): since F-369/N-213 the k=1 OP_PUSH_TX ECDSA signature is
 * unused on the stateful prepareCall path (`buildStatefulPrefix` ignores it and
 * the on-chain script derives it from the preimage), yet the path still
 * computed -- and discarded -- one per pass via `computeOpPushTx`.
 *
 * The fix adds a preimage-only variant (`computeOpPushTxPreimage`) and uses it
 * on the stateful branch. `computeOpPushTx` itself is public API (README) and
 * is unchanged.
 *
 * What this proves: a stateful `prepareCall` performs zero ECDSA signs with the
 * OP_PUSH_TX key (k=1), counted by spying `PrivateKey.prototype.sign` and
 * filtering on the key; the control shows the spy does see `computeOpPushTx`
 * sign. Byte-identity of the prepared output is proven by the existing
 * stateful-merge-prepared replays and the F-369 / constructor-slots tests.
 * What it does not prove: anything about the stateless / terminal paths.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { compile } from 'runar-compiler';
import { PrivateKey, Transaction } from '@bsv/sdk';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { computeOpPushTx, computeOpPushTxPreimage } from '../oppushtx.js';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000007';
const K1_HEX = '00'.repeat(31) + '01';

const SRC = `
  import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
  import type { PubKey, Sig } from 'runar-lang';

  class OwnerBump extends StatefulSmartContract {
    readonly owner: PubKey;
    counter: bigint;
    constructor(owner: PubKey, counter: bigint) {
      super(owner, counter);
      this.owner = owner;
      this.counter = counter;
    }
    public bump(sig: Sig): void {
      assert(checkSig(sig, this.owner));
      this.counter = this.counter + 1n;
    }
  }
`;

function spyOnK1Signs(): { count: () => number } {
  const orig = PrivateKey.prototype.sign;
  let n = 0;
  vi.spyOn(PrivateKey.prototype, 'sign').mockImplementation(function (this: PrivateKey, ...args: unknown[]) {
    if (this.toHex() === K1_HEX) n++;
    return (orig as (...a: unknown[]) => unknown).apply(this, args) as ReturnType<typeof orig>;
  } as typeof orig);
  return { count: () => n };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('N-253 -- stateful prepareCall does not compute an OP_PUSH_TX signature', () => {
  it('prepareCall on a stateful method performs zero k=1 signs', async () => {
    const result = compile(SRC, { fileName: 'OwnerBump.runar.ts' });
    if (!result.artifact) throw new Error('compile failed');
    const provider = new MockProvider('testnet');
    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    const pubKeyHex = await signer.getPublicKey();
    provider.addUtxo(address, {
      txid: SIGNER_KEY.slice(0, 64),
      outputIndex: 0,
      satoshis: 500_000,
      script: buildP2PKHScript(pubKeyHex),
    });
    const contract = new RunarContract(result.artifact, [pubKeyHex, 0n]);
    contract.connect(provider, signer);
    await contract.deploy(provider, signer, {});

    const spy = spyOnK1Signs();
    const prepared = await contract.prepareCall('bump', [null]);
    expect(prepared.sighash).not.toBe('');
    expect(spy.count()).toBe(0);
  });

  it('control: computeOpPushTx still signs with k=1; the preimage-only variant matches its preimage without signing', () => {
    const spy = spyOnK1Signs();
    const tx = new Transaction();
    tx.addInput({ sourceTXID: 'aa'.repeat(32), sourceOutputIndex: 0, sequence: 0xffffffff });
    const subscript = '51';
    const full = computeOpPushTx(tx, 0, subscript, 1000);
    expect(spy.count()).toBe(1);
    const only = computeOpPushTxPreimage(tx, 0, subscript, 1000);
    expect(spy.count()).toBe(1);
    expect(only.preimageHex).toBe(full.preimageHex);
  });
});
