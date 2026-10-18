/**
 * N-043: WalletProvider.getUtxos() is the reference for the cross-tier
 * "output reported without a usable locking script" policy: such an output is
 * DROPPED (fail-closed). Go, Python, Ruby and Zig used to keep it.
 *
 * PROVES: a spendable wallet output whose lockingScript is '' or absent is not
 * returned, while the matching P2PKH output next to it is.
 * DOES NOT PROVE: behaviour against a real BRC-100 wallet.
 */

import { describe, it, expect } from 'vitest';
import { WalletProvider } from '../providers/wallet-provider.js';
import { buildP2PKHScript } from '../script-utils.js';
import type { Signer } from '../signers/signer.js';
import type { WalletClient } from '@bsv/sdk';

const PUB = '02' + '11'.repeat(32);
const stubSigner: Signer = {
  async getPublicKey() { return PUB; },
  async getAddress() { return '1BitcoinAddress'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

describe('N-043: getUtxos drops an output with no usable locking script', () => {
  it('drops empty / missing scripts and keeps the matching P2PKH output', async () => {
    const good = buildP2PKHScript(PUB);
    const wallet = {
      async listOutputs() {
        return {
          outputs: [
            { outpoint: `${'aa'.repeat(32)}.0`, satoshis: 1000, spendable: true, lockingScript: good },
            { outpoint: `${'bb'.repeat(32)}.1`, satoshis: 2000, spendable: true, lockingScript: '' },
            { outpoint: `${'cc'.repeat(32)}.2`, satoshis: 3000, spendable: true },
          ],
        };
      },
    } as unknown as WalletClient;
    const p = new WalletProvider({ wallet, signer: stubSigner, basket: 'b' });
    const utxos = await p.getUtxos('ignored');
    expect(utxos.map((u) => [u.txid, u.outputIndex, u.script])).toEqual([['aa'.repeat(32), 0, good]]);
  });
});
