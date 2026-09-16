/**
 * M-1 (round-three audit): `MockProvider` disabled BOTH value conservation
 * and the fee floor whenever a SINGLE input's outpoint was unregistered.
 *
 * Both checks sat inside `if (allInputsKnown)`, and the P1-1 hardening that
 * fails closed on an un-validatable broadcast only fired when `validated ===
 * 0` — i.e. when EVERY input was unknown. One known input was enough to
 * satisfy P1-1 while leaving `allInputsKnown` false, so a transaction that
 * creates satoshis from nothing was acked. Measured before the fix, same
 * overspend, the only difference being one extra unregistered input:
 *
 *   all-known      : REJECTED: fee too low: paid -999000 sats, required >= 7
 *   partially-known: ACCEPTED {"validated":1,"skipped":1}
 *
 * The fix makes an unregistered input a fail-closed condition in its own
 * right (`requireKnownInputs`, default ON). A test that legitimately needs an
 * input this provider was never told about must now say so — explicitly and
 * visibly — via `allowUnknownInputs()` / `{ allowUnknownInputs: true }`,
 * rather than getting conservation and the fee floor switched off by
 * omission and never noticing.
 */
import { describe, it, expect } from 'vitest';
import { Transaction, UnlockingScript, LockingScript } from '@bsv/sdk';
import { MockProvider } from '../providers/mock.js';

const KNOWN_TXID = 'aa'.repeat(32);
const UNKNOWN_TXID = 'bb'.repeat(32);

function anyoneCanSpendInput(txid: string, vout: number) {
  return {
    sourceTXID: txid,
    sourceOutputIndex: vout,
    unlockingScript: new UnlockingScript(),
    sequence: 0xffffffff,
  };
}

/** One registered 1000-sat OP_TRUE input, one input this provider has never
 * been told about, and an output 1000x the known input's value. */
function makeOverspendTx(): Transaction {
  const tx = new Transaction();
  tx.addInput(anyoneCanSpendInput(KNOWN_TXID, 0));
  tx.addInput(anyoneCanSpendInput(UNKNOWN_TXID, 0));
  tx.addOutput({ satoshis: 1_000_000, lockingScript: LockingScript.fromHex('51') });
  return tx;
}

function providerWithKnownUtxo(opts?: { allowUnknownInputs?: boolean }): MockProvider {
  const provider = new MockProvider('testnet', opts);
  provider.addUtxo('funder', {
    txid: KNOWN_TXID,
    outputIndex: 0,
    satoshis: 1000,
    script: '51', // OP_TRUE — script-valid regardless of amounts
  });
  return provider;
}

describe('M-1 — one unregistered input must not disable conservation + fee floor', () => {
  it('RED: a partially-known overspend (999,000 sats from nothing) is rejected', async () => {
    const provider = providerWithKnownUtxo();
    await expect(provider.broadcast(makeOverspendTx())).rejects.toThrow(
      /unregistered|unknown/i,
    );
  });

  it('RED: the rejection names the offending outpoint and how to register it', async () => {
    const provider = providerWithKnownUtxo();
    await expect(provider.broadcast(makeOverspendTx())).rejects.toThrow(
      new RegExp(`${UNKNOWN_TXID}:0`),
    );
  });

  it('RED: a partially-known tx that is NOT an overspend is rejected too — the point is that its conservation was never checked, not that it failed', async () => {
    const provider = providerWithKnownUtxo();
    const tx = new Transaction();
    tx.addInput(anyoneCanSpendInput(KNOWN_TXID, 0));
    tx.addInput(anyoneCanSpendInput(UNKNOWN_TXID, 0));
    tx.addOutput({ satoshis: 800, lockingScript: LockingScript.fromHex('51') });
    await expect(provider.broadcast(tx)).rejects.toThrow(/unregistered|unknown/i);
  });

  it('CONTROL (teeth): a genuinely-valid partially-known tx still broadcasts once the test opts out EXPLICITLY', async () => {
    const provider = providerWithKnownUtxo({ allowUnknownInputs: true });
    const tx = new Transaction();
    tx.addInput(anyoneCanSpendInput(KNOWN_TXID, 0));
    tx.addInput(anyoneCanSpendInput(UNKNOWN_TXID, 0));
    tx.addOutput({ satoshis: 800, lockingScript: LockingScript.fromHex('51') });

    const txid = await provider.broadcast(tx);
    expect(txid).toMatch(/^[0-9a-f]{64}$/);
    // ...and the opt-out is auditable: the skip is counted, not silent.
    expect(provider.getValidationStats()).toEqual({ validated: 1, skipped: 1 });
  });

  it('CONTROL (teeth): allowUnknownInputs() still runs `Spend` on the inputs it DOES know', async () => {
    const provider = new MockProvider('testnet', { allowUnknownInputs: true });
    provider.addUtxo('funder', {
      txid: KNOWN_TXID,
      outputIndex: 1,
      satoshis: 1000,
      script: '00', // OP_FALSE — unsatisfiable
    });
    const tx = new Transaction();
    tx.addInput(anyoneCanSpendInput(KNOWN_TXID, 1));
    tx.addInput(anyoneCanSpendInput(UNKNOWN_TXID, 0));
    tx.addOutput({ satoshis: 800, lockingScript: LockingScript.fromHex('51') });

    await expect(provider.broadcast(tx)).rejects.toThrow(/input 0/);
  });

  it('CONTROL (teeth): an all-known tx is unaffected — valid acks, overspend rejects', async () => {
    const provider = providerWithKnownUtxo();
    const good = new Transaction();
    good.addInput(anyoneCanSpendInput(KNOWN_TXID, 0));
    good.addOutput({ satoshis: 800, lockingScript: LockingScript.fromHex('51') });
    await expect(provider.broadcast(good)).resolves.toMatch(/^[0-9a-f]{64}$/);

    const bad = new Transaction();
    bad.addInput(anyoneCanSpendInput(KNOWN_TXID, 0));
    bad.addOutput({ satoshis: 1_000_000, lockingScript: LockingScript.fromHex('51') });
    await expect(provider.broadcast(bad)).rejects.toThrow(/fee too low/);
  });

  it('CONTROL: a zero-input tx is not caught by the unknown-input gate (it fails the fee floor, as it did before)', async () => {
    const provider = providerWithKnownUtxo();
    const tx = new Transaction();
    tx.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex('51') });
    const err = await provider.broadcast(tx).then(
      () => { throw new Error('expected a rejection'); },
      (e: unknown) => e as Error,
    );
    expect(err.message).toMatch(/fee too low/);
    expect(err.message).not.toMatch(/unregistered/);
  });

});
