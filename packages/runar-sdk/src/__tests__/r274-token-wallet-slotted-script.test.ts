/**
 * R-274 (CL-GAP-033): TokenWallet.getUtxos() filtered with a literal
 * `utxo.script.startsWith(artifact.script)`, which silently returns EMPTY for
 * any token contract that bakes a constructor arg into its code part.
 *
 * `artifact.script` is the TEMPLATE: each constructor slot holds a one-byte
 * OP_0 placeholder that deployment replaces with the encoded argument. A
 * deployed instance therefore does NOT start with the template whenever a
 * constructorSlot sits inside the code part — a shape this codebase supports
 * (slot-layout.ts exists for it) and TokenWallet's only test did not exercise,
 * because its fixture had no slots.
 *
 * The consequence is silent: getBalance() returns 0n for a wallet that holds
 * tokens, and transfer() throws "no token UTXOs found".
 *
 * The filter cannot compare past the first slot — the substituted argument is
 * variable-length, so every byte after it is at a shifted offset. It now
 * matches on the template up to the FIRST slot, which every deployed instance
 * of this contract really does share, and says so.
 */

import { describe, it, expect } from 'vitest';
import { TokenWallet } from '../tokens.js';
import { MockProvider } from '../providers/mock.js';
import type { RunarArtifact, UTXO } from '../types.js';
import type { Signer } from '../signers/signer.js';

const FAKE_TXID = 'aa'.repeat(32);

function makeMockSigner(): Signer {
  return {
    async getPublicKey() { return '02' + '11'.repeat(32); },
    async getAddress() { return 'mocked-address'; },
    async sign() { return '00'.repeat(71); },
  } as unknown as Signer;
}

/**
 * A template whose code part carries a constructor slot: the OP_0 placeholder
 * at byte offset 2 is replaced at deploy time by the encoded `supply`.
 *
 *   bytes:  0  1  2   3  4
 *           76 a9 00  88 ac
 *                 ^ constructorSlots[0].byteOffset
 */
function slottedArtifact(): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'FungibleToken',
    abi: {
      constructor: { params: [{ name: 'supply', type: 'bigint' }] },
      methods: [{ name: 'transfer', params: [], isPublic: true }],
    },
    script: '76a9' + '00' + '88ac',
    asm: '',
    constructorSlots: [{ paramIndex: 0, byteOffset: 2 }],
    buildTimestamp: '2026-01-01T00:00:00Z',
  } as unknown as RunarArtifact;
}

/** The same contract as deployed: OP_0 replaced by a 2-byte push of 1000. */
const DEPLOYED_SCRIPT = '76a9' + '02e803' + '88ac' + '6a' + '0100';

describe('R-274: TokenWallet finds UTXOs of a contract with constructor slots', () => {
  it('finds a deployed instance whose template has a slot in the code part', async () => {
    const provider = new MockProvider();
    const signer = makeMockSigner();

    const mine: UTXO = {
      txid: FAKE_TXID,
      outputIndex: 0,
      satoshis: 10_000,
      script: DEPLOYED_SCRIPT,
    };
    const someoneElses: UTXO = {
      txid: 'bb'.repeat(32),
      outputIndex: 0,
      satoshis: 5_000,
      script: 'deadbeef6a0100',
    };
    provider.addUtxo('mocked-address', mine);
    provider.addUtxo('mocked-address', someoneElses);

    const wallet = new TokenWallet(slottedArtifact(), provider, signer);
    const utxos = await wallet.getUtxos();

    expect(utxos.map((u) => u.txid)).toEqual([FAKE_TXID]);
  });

  it('still rejects a script that diverges before the first slot', async () => {
    const provider = new MockProvider();
    const signer = makeMockSigner();
    provider.addUtxo('mocked-address', {
      txid: 'cc'.repeat(32),
      outputIndex: 0,
      satoshis: 1_000,
      // Same length and shape, different code bytes before the slot.
      script: '76aa' + '02e803' + '88ac',
    });

    const wallet = new TokenWallet(slottedArtifact(), provider, signer);
    expect(await wallet.getUtxos()).toEqual([]);
  });

  it('is unchanged for a template with no slots', async () => {
    const provider = new MockProvider();
    const signer = makeMockSigner();
    const artifact = { ...slottedArtifact(), script: '76a988ac', constructorSlots: [] };

    provider.addUtxo('mocked-address', {
      txid: FAKE_TXID, outputIndex: 0, satoshis: 10_000, script: '76a988ac' + '6a' + '0100',
    });
    provider.addUtxo('mocked-address', {
      txid: 'bb'.repeat(32), outputIndex: 0, satoshis: 5_000, script: 'deadbeef6a0100',
    });

    const wallet = new TokenWallet(artifact as RunarArtifact, provider, signer);
    const utxos = await wallet.getUtxos();
    expect(utxos.map((u) => u.txid)).toEqual([FAKE_TXID]);
  });
});
