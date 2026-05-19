// ---------------------------------------------------------------------------
// runar-sdk/__tests__/intent-witness-values.test.ts
//
// R-6 — SDK consumer support for intent-intrinsic auto-injected witness params
// (`_prevOutScript_<i>`, `_serialisedOutputs`).
//
// Covers:
//   - filter: auto-injected witness params are NOT part of the user arg count
//   - setters: setPrevOutScript / setSerialisedOutputs store witness bytes
//   - errors: missing witness raises a typed WitnessValueMissingError
//   - wiring: witness bytes are appended to the primary unlocking script in
//     ABI order (`_prevOutScript_*` first, then `_serialisedOutputs`), AFTER
//     the BIP-143 preimage push and BEFORE the method selector
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { WitnessValueMissingError } from '../errors.js';
import type { RunarArtifact, StateField } from 'runar-ir-schema';
import type { UTXO } from '../types.js';

const PRIV_KEY = '0000000000000000000000000000000000000000000000000000000000000001';

function makeFundingUtxo(satoshis: number, index = 0): UTXO {
  return {
    txid: 'aabbccdd'.repeat(8),
    outputIndex: index,
    satoshis,
    script: '76a914' + '00'.repeat(20) + '88ac',
  };
}

/**
 * Build a stateful artifact whose `move` method's ABI carries the
 * compiler-auto-injected continuation + intent-witness params. The on-chain
 * script is just OP_TRUE (`51`) so spending always succeeds — we only assert
 * on the unlocking-script BYTES, not on Bitcoin Script execution.
 */
function makeArtifactWithIntentWitness(
  extraWitnessParams: { prevOutInputs: number[]; serialised: boolean },
): RunarArtifact {
  const stateFields: StateField[] = [
    { name: 'count', type: 'bigint', index: 0 },
  ];

  const witnessParams = [
    ...extraWitnessParams.prevOutInputs.map((i) => ({
      name: `_prevOutScript_${i}`,
      type: 'ByteString',
    })),
    ...(extraWitnessParams.serialised
      ? [{ name: '_serialisedOutputs', type: 'ByteString' }]
      : []),
  ];

  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'IntentWitnessTest',
    asm: '',
    buildTimestamp: '2026-05-18T00:00:00.000Z',
    script: '51',
    abi: {
      constructor: { params: [{ name: 'count', type: 'bigint' }] },
      methods: [
        {
          name: 'move',
          isPublic: true,
          params: [
            // One ordinary user param
            { name: 'amount', type: 'bigint' },
            // Compiler-injected continuation params for stateful methods
            { name: '_changePKH', type: 'Ripemd160' },
            { name: '_changeAmount', type: 'bigint' },
            { name: '_newAmount', type: 'bigint' },
            { name: 'txPreimage', type: 'SigHashPreimage' },
            // Compiler-injected intent witness params (this is what R-6 covers)
            ...witnessParams,
          ],
        },
      ],
    },
    stateFields,
    codeSeparatorIndex: 0,
  };
}

describe('R-6 — intent-intrinsic witness values', () => {
  // -------------------------------------------------------------------------
  // Filter: arg-count check excludes _prevOutScript_* / _serialisedOutputs
  // -------------------------------------------------------------------------

  describe('arg-count filter', () => {
    it('does NOT count _prevOutScript_<i> or _serialisedOutputs in the user-facing arg count', async () => {
      const signer = new LocalSigner(PRIV_KEY);
      const address = await signer.getAddress();
      const provider = new MockProvider();
      provider.addUtxo(address, makeFundingUtxo(100_000));

      const artifact = makeArtifactWithIntentWitness({ prevOutInputs: [0, 1], serialised: true });
      const contract = new RunarContract(artifact, [0n]);
      await contract.deploy(provider, signer, { satoshis: 50_000 });

      // Supply witnesses so we don't trip WitnessValueMissingError — we're
      // asserting the filter passes the arg count check.
      contract.setPrevOutScript(0, 'aa');
      contract.setPrevOutScript(1, 'bb');
      contract.setSerialisedOutputs('cc');

      provider.addUtxo(address, makeFundingUtxo(100_000, 1));

      // User passes exactly 1 arg (just `amount`). Without the new filter
      // the SDK would have complained "expects 7 args, got 1" because the
      // ABI lists amount + 3 continuation params + 2 prevOutScripts + 1
      // serialisedOutputs (after filtering txPreimage out of the legacy
      // check). With the new filter only `amount` is user-facing.
      await contract.call('move', [123n], provider, signer, {
        newState: { count: 1n },
      });

      // No assertion error / no exception ⇒ filter accepted 1 user arg.
      expect(contract.state.count).toBe(1n);
    });

    it('still rejects user-arg count mismatches for non-auto-injected params', async () => {
      const signer = new LocalSigner(PRIV_KEY);
      const address = await signer.getAddress();
      const provider = new MockProvider();
      provider.addUtxo(address, makeFundingUtxo(100_000));

      const artifact = makeArtifactWithIntentWitness({ prevOutInputs: [0], serialised: true });
      const contract = new RunarContract(artifact, [0n]);
      await contract.deploy(provider, signer, { satoshis: 50_000 });

      provider.addUtxo(address, makeFundingUtxo(100_000, 1));

      // Pass 2 args when only `amount` is user-facing
      let err: unknown = null;
      try {
        await contract.call('move', [1n, 2n], provider, signer);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toMatch(/expects 1 args, got 2/);
    });
  });

  // -------------------------------------------------------------------------
  // Missing witness ⇒ typed WitnessValueMissingError
  // -------------------------------------------------------------------------

  describe('missing witness raises WitnessValueMissingError', () => {
    it('throws when a `_prevOutScript_<i>` witness is not set', async () => {
      const signer = new LocalSigner(PRIV_KEY);
      const address = await signer.getAddress();
      const provider = new MockProvider();
      provider.addUtxo(address, makeFundingUtxo(100_000));

      const artifact = makeArtifactWithIntentWitness({ prevOutInputs: [0], serialised: false });
      const contract = new RunarContract(artifact, [0n]);
      await contract.deploy(provider, signer, { satoshis: 50_000 });
      provider.addUtxo(address, makeFundingUtxo(100_000, 1));

      let err: unknown = null;
      try {
        await contract.call('move', [1n], provider, signer);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(WitnessValueMissingError);
      const wErr = err as WitnessValueMissingError;
      expect(wErr.paramName).toBe('_prevOutScript_0');
      expect(wErr.methodName).toBe('move');
      expect(wErr.contractName).toBe('IntentWitnessTest');
    });

    it('throws when `_serialisedOutputs` is not set', async () => {
      const signer = new LocalSigner(PRIV_KEY);
      const address = await signer.getAddress();
      const provider = new MockProvider();
      provider.addUtxo(address, makeFundingUtxo(100_000));

      const artifact = makeArtifactWithIntentWitness({ prevOutInputs: [], serialised: true });
      const contract = new RunarContract(artifact, [0n]);
      await contract.deploy(provider, signer, { satoshis: 50_000 });
      provider.addUtxo(address, makeFundingUtxo(100_000, 1));

      let err: unknown = null;
      try {
        await contract.call('move', [1n], provider, signer);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(WitnessValueMissingError);
      expect((err as WitnessValueMissingError).paramName).toBe('_serialisedOutputs');
    });
  });

  // -------------------------------------------------------------------------
  // Wiring: witness bytes appear in the broadcast unlocking script
  // -------------------------------------------------------------------------

  describe('witness bytes appear in primary unlocking script', () => {
    it('appends `_prevOutScript_*` witnesses (multi-input) in ABI order', async () => {
      const signer = new LocalSigner(PRIV_KEY);
      const address = await signer.getAddress();
      const provider = new MockProvider();
      provider.addUtxo(address, makeFundingUtxo(100_000));

      const artifact = makeArtifactWithIntentWitness({ prevOutInputs: [0, 1], serialised: false });
      const contract = new RunarContract(artifact, [0n]);
      await contract.deploy(provider, signer, { satoshis: 50_000 });
      provider.addUtxo(address, makeFundingUtxo(100_000, 1));

      const w0Hex = 'deadbeef';
      const w1Hex = 'cafebabe';
      contract.setPrevOutScript(0, w0Hex);
      contract.setPrevOutScript(1, w1Hex);

      await contract.call('move', [1n], provider, signer, { newState: { count: 1n } });

      const broadcastedTxs = provider.getBroadcastedTxs();
      expect(broadcastedTxs.length).toBe(2); // deploy + call
      const callTxHex = broadcastedTxs[1]!;

      // Find both witness pushes in ABI order. PUSHDATA for 4 bytes = `04` + data.
      const push0 = '04' + w0Hex;
      const push1 = '04' + w1Hex;
      const idx0 = callTxHex.indexOf(push0);
      const idx1 = callTxHex.indexOf(push1);
      expect(idx0).toBeGreaterThanOrEqual(0);
      expect(idx1).toBeGreaterThan(idx0); // _prevOutScript_1 follows _prevOutScript_0
    });

    it('appends both `_prevOutScript_<i>` and `_serialisedOutputs` with prevOuts FIRST', async () => {
      const signer = new LocalSigner(PRIV_KEY);
      const address = await signer.getAddress();
      const provider = new MockProvider();
      provider.addUtxo(address, makeFundingUtxo(100_000));

      const artifact = makeArtifactWithIntentWitness({ prevOutInputs: [0], serialised: true });
      const contract = new RunarContract(artifact, [0n]);
      await contract.deploy(provider, signer, { satoshis: 50_000 });
      provider.addUtxo(address, makeFundingUtxo(100_000, 1));

      const prevOutHex = '11223344';
      const serialisedHex = '55667788';
      contract.setPrevOutScript(0, prevOutHex);
      contract.setSerialisedOutputs(serialisedHex);

      await contract.call('move', [1n], provider, signer, { newState: { count: 1n } });

      const callTxHex = provider.getBroadcastedTxs()[1]!;
      const pushPrev = '04' + prevOutHex;
      const pushSerial = '04' + serialisedHex;
      const idxPrev = callTxHex.indexOf(pushPrev);
      const idxSerial = callTxHex.indexOf(pushSerial);
      expect(idxPrev).toBeGreaterThanOrEqual(0);
      expect(idxSerial).toBeGreaterThan(idxPrev);
    });

    it('accepts witness values as Uint8Array', async () => {
      const signer = new LocalSigner(PRIV_KEY);
      const address = await signer.getAddress();
      const provider = new MockProvider();
      provider.addUtxo(address, makeFundingUtxo(100_000));

      const artifact = makeArtifactWithIntentWitness({ prevOutInputs: [0], serialised: false });
      const contract = new RunarContract(artifact, [0n]);
      await contract.deploy(provider, signer, { satoshis: 50_000 });
      provider.addUtxo(address, makeFundingUtxo(100_000, 1));

      contract.setPrevOutScript(0, new Uint8Array([0xab, 0xcd]));
      await contract.call('move', [1n], provider, signer, { newState: { count: 1n } });

      const callTxHex = provider.getBroadcastedTxs()[1]!;
      // 2-byte push: 02 + abcd
      expect(callTxHex.includes('02abcd')).toBe(true);
    });

    it('rejects hex inputs with invalid characters', () => {
      const artifact = makeArtifactWithIntentWitness({ prevOutInputs: [0], serialised: false });
      const contract = new RunarContract(artifact, [0n]);
      expect(() => contract.setPrevOutScript(0, 'not-hex!')).toThrow();
    });

    it('rejects hex inputs with odd length', () => {
      const artifact = makeArtifactWithIntentWitness({ prevOutInputs: [0], serialised: false });
      const contract = new RunarContract(artifact, [0n]);
      expect(() => contract.setSerialisedOutputs('abc')).toThrow();
    });
  });
});
