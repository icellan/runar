/**
 * N-426 — the stateful change-address guard, TS reference + shared vector.
 *
 * A stateful covenant that takes `_changePKH` rebuilds its change output from
 * hash160(changePubKey ?? signer pubkey). A call whose `changeAddress` names a
 * different key therefore builds a spend the network rejects. The SDK must
 * refuse that BEFORE signing/broadcast, with the one message recorded in
 * `n426-change-address-guard.json` (every tier's native test replays it).
 *
 * Proves (TS): changeAddress alone for another key is refused with the shared
 * message and nothing is broadcast; changeAddress + matching changePubKey and
 * changeAddress == the signer's own address are accepted, and the broadcast tx
 * was Spend-validated by MockProvider on every input.
 * Does not prove: the other six SDKs (each has its own N-426 test against the
 * same JSON), the terminal path, or a live node.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RunarContract } from '../../packages/runar-sdk/src/contract.js';
import { MockProvider } from '../../packages/runar-sdk/src/providers/mock.js';
import { LocalSigner } from '../../packages/runar-sdk/src/signers/local.js';

const here = dirname(fileURLToPath(import.meta.url));
const guard = JSON.parse(readFileSync(join(here, 'n426-change-address-guard.json'), 'utf8'));
const base = JSON.parse(readFileSync(join(here, guard.baseVector), 'utf8'));

async function setup() {
  const signer = new LocalSigner(base.privKeyHex);
  const address = await signer.getAddress();
  const provider = new MockProvider('testnet');
  provider.addUtxo(address, base.fundingUtxo);
  provider.addContractUtxo(base.contractUtxo.script, base.contractUtxo);
  const artifact = JSON.parse(typeof base.artifact === 'string' ? base.artifact : JSON.stringify(base.artifact));
  const contract = RunarContract.fromUtxo(artifact, base.contractUtxo);
  contract.connect(provider, signer);
  return { contract, provider, address };
}

const expected = (addr: string) => (guard.message as string).replace('{changeAddress}', addr);

describe('N-426 stateful change-address guard (TS)', () => {
  it('vector addresses match the keys they claim', async () => {
    expect(await new LocalSigner(base.privKeyHex).getAddress()).toBe(guard.ownAddress);
    const other = new LocalSigner(guard.otherPrivKeyHex);
    expect(await other.getAddress()).toBe(guard.otherAddress);
    expect(await other.getPublicKey()).toBe(guard.otherPubKeyHex);
  });

  it('refuses changeAddress for another key without changePubKey, before any broadcast', async () => {
    const { contract, provider } = await setup();
    await expect(
      contract.call('increment', [null], { changeAddress: guard.otherAddress }),
    ).rejects.toThrow(expected(guard.otherAddress));
    expect(provider.getBroadcastedTxs().length).toBe(0);
  });

  it('prepareCall refuses it too', async () => {
    const { contract } = await setup();
    await expect(
      contract.prepareCall('increment', [null], { changeAddress: guard.otherAddress }),
    ).rejects.toThrow(expected(guard.otherAddress));
  });

  it('accepts changeAddress with the matching changePubKey (Spend-validated)', async () => {
    const { contract, provider } = await setup();
    await contract.call('increment', [null], {
      changeAddress: guard.otherAddress,
      changePubKey: guard.otherPubKeyHex,
    });
    expect(provider.getBroadcastedTxs().length).toBe(1);
    expect(provider.getValidationStats().validated).toBe(2);
  });

  it("accepts changeAddress equal to the signer's own address without changePubKey", async () => {
    const { contract, provider, address } = await setup();
    expect(address).toBe(guard.ownAddress);
    await contract.call('increment', [null], { changeAddress: address });
    expect(provider.getBroadcastedTxs().length).toBe(1);
  });
});
