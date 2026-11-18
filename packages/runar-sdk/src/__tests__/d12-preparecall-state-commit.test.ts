/**
 * D12 SDK-F1 / SDK-F2 / SDK-F4: `prepareCall` must never leave the tracked
 * state (or UTXO) changed. It computes the post-call state into the
 * PreparedCall; only a successful `finalizeCall` commits it.
 *
 * Before the fix, prepareCall wrote the post-call state into the contract
 * and then did fallible work (fee rate, UTXO lookup, funding signer,
 * maxFundingInputs). A throw there, an abandoned PreparedCall, or a second
 * prepare left `state` at n+1 while the chain was at n, and every later call
 * was refused by the covenant until a manual `fromTxId` resync.
 *
 * Proves (against MockProvider's @bsv/sdk Spend replay): after each failure
 * mode the state and UTXO equal the pre-call values and the next honest call
 * is accepted by the interpreter; a superseded prepare's failure does not
 * clobber the state another finalize committed; an underfunded call is
 * refused locally, before `broadcast` is reached.
 * Does not prove: other SDK tiers (each has its own test).
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { Signer } from '../signers/signer.js';

const SRC = `import { StatefulSmartContract, assert } from 'runar-lang';

class Gate extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(k: bigint) {
    assert(k === 7n);
    this.n = this.n + 1n;
  }
}
`;

function artifact() {
  const r = compile(SRC, { fileName: 'Gate.runar.ts' });
  if (!r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  return r.artifact;
}

async function deployed(fundingSats = 5_000_000) {
  const signer = new LocalSigner('11'.repeat(32));
  const provider = new MockProvider();
  const addr = await signer.getAddress();
  provider.addUtxo(addr, {
    txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5_000_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  const contract = new RunarContract(artifact(), [0n]);
  contract.connect(provider, signer);
  await contract.deploy({ satoshis: 50_000 });
  return { contract, provider, signer, addr, fundingSats };
}

describe('D12 SDK-F1: a throw inside prepareCall leaves state and UTXO untouched', () => {
  const cases: Array<[string, (p: MockProvider) => (() => void) | void, Record<string, unknown>?]> = [
    ['getUtxos network error', (p) => {
      const orig = p.getUtxos.bind(p);
      p.getUtxos = async () => { throw new Error('ECONNRESET'); };
      return () => { p.getUtxos = orig; };
    }],
    ['getFeeRate error', (p) => {
      const orig = p.getFeeRate.bind(p);
      p.getFeeRate = async () => { throw new Error('503'); };
      return () => { p.getFeeRate = orig; };
    }],
    ['maxFundingInputs = 0', () => undefined, { maxFundingInputs: 0 }],
  ];
  for (const [name, mutate, opts] of cases) {
    it(name, async () => {
      const { contract, provider } = await deployed();
      const utxoBefore = contract.getUtxo();
      const undo = mutate(provider);
      await expect(contract.call('bump', [7n], opts)).rejects.toThrow();
      expect(contract.state).toEqual({ n: 0n });
      expect(contract.getUtxo()).toEqual(utxoBefore);
      undo?.();
      await contract.call('bump', [7n]);
      expect(contract.state).toEqual({ n: 1n });
    });
  }

  it('funding signer declines', async () => {
    const { contract, provider, signer } = await deployed();
    const declining: Signer = {
      getPublicKey: () => signer.getPublicKey(),
      getAddress: () => signer.getAddress(),
      sign: async () => { throw new Error('user declined'); },
    } as Signer;
    contract.connect(provider, declining);
    await expect(contract.call('bump', [7n])).rejects.toThrow(/declined/);
    expect(contract.state).toEqual({ n: 0n });
    contract.connect(provider, signer);
    await contract.call('bump', [7n]);
    expect(contract.state).toEqual({ n: 1n });
  });
});

describe('D12 SDK-F2: an abandoned or superseded PreparedCall changes nothing', () => {
  it('abandoned prepareCall leaves state at the chain state', async () => {
    const { contract } = await deployed();
    const utxoBefore = contract.getUtxo();
    await contract.prepareCall('bump', [7n]);
    expect(contract.state).toEqual({ n: 0n });
    expect(contract.getUtxo()).toEqual(utxoBefore);
    await contract.call('bump', [7n]);
    expect(contract.state).toEqual({ n: 1n });
  });

  it('second prepare finalizes against the chain state', async () => {
    const { contract } = await deployed();
    await contract.prepareCall('bump', [7n]);
    const b = await contract.prepareCall('bump', [7n]);
    await contract.finalizeCall(b, {});
    expect(contract.state).toEqual({ n: 1n });
  });

  it('a failing finalize does not clobber the state another finalize committed', async () => {
    const { contract, provider } = await deployed();
    const a = await contract.prepareCall('bump', [7n]);
    const b = await contract.prepareCall('bump', [7n]);
    await contract.finalizeCall(b, {});
    expect(contract.state).toEqual({ n: 1n });
    // a's broadcast fails (e.g. the node refuses the now-spent outpoint): the
    // state b committed must stay.
    provider.broadcast = async () => { throw new Error('txn-mempool-conflict'); };
    await expect(contract.finalizeCall(a, {})).rejects.toThrow(/conflict/);
    expect(contract.state).toEqual({ n: 1n });
  });
});

describe('D12 SDK-F4: an underfunded call is refused before broadcast', () => {
  // Short (not missing) funding: a caller whose only UTXO is f sats. The fee
  // the tx needs is found by scanning; one sat below it is refused locally
  // (broadcast never reached), the exact amount is broadcast and accepted.
  it('short funding: one sat below the required fee is refused locally, the exact fee is accepted', async () => {
    const PLAIN = `import { StatefulSmartContract } from 'runar-lang';
class P extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public plain() { this.count = this.count + 1n; }
}
`;
    const r = compile(PLAIN, { fileName: 'P.runar.ts' });
    if (!r.artifact) throw new Error(JSON.stringify(r.diagnostics));
    const attempt = async (f: number) => {
      const deployer = new LocalSigner('11'.repeat(32));
      const provider = new MockProvider();
      provider.addUtxo(await deployer.getAddress(), {
        txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 200_000,
        script: buildP2PKHScript(await deployer.getPublicKey()),
      });
      const c = new RunarContract(r.artifact!, [0n]);
      await c.deploy(provider, deployer, { satoshis: 50_000 });
      const caller = new LocalSigner('22'.repeat(32));
      provider.addUtxo(await caller.getAddress(), {
        txid: 'bb'.repeat(32), outputIndex: 0, satoshis: f,
        script: buildP2PKHScript(await caller.getPublicKey()),
      });
      let broadcasts = 0;
      const origB = provider.broadcast.bind(provider);
      provider.broadcast = async (tx) => { broadcasts++; return origB(tx); };
      try {
        await c.call('plain', [], provider, caller);
        return { ok: true as const, broadcasts, state: c.state };
      } catch (e) {
        return { ok: false as const, broadcasts, err: (e as Error).message, state: c.state };
      }
    };
    let need = -1;
    for (let f = 200; f <= 320; f++) {
      if ((await attempt(f)).ok) { need = f; break; }
    }
    expect(need).toBeGreaterThan(200);
    const below = await attempt(need - 1);
    expect(below.ok).toBe(false);
    expect(below.err).toMatch(/insufficient funds/);
    expect(below.broadcasts).toBe(0);
    expect(below.state).toEqual({ count: 0n });
    const exact = await attempt(need);
    expect(exact.ok).toBe(true);
    expect(exact.state).toEqual({ count: 1n });
  });

  it('no funding UTXOs -> local insufficient-funds error, broadcast not reached', async () => {
    const { contract, provider } = await deployed();
    provider.getUtxos = async () => [];
    let broadcasts = 0;
    const origB = provider.broadcast.bind(provider);
    provider.broadcast = async (tx) => { broadcasts++; return origB(tx); };
    await expect(contract.call('bump', [7n])).rejects.toThrow(/insufficient funds/i);
    expect(broadcasts).toBe(0);
    expect(contract.state).toEqual({ n: 0n });
  });
});
