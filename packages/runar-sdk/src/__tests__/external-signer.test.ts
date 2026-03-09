import { describe, it, expect, vi } from 'vitest';
import { ExternalSigner } from '../signers/external.js';

describe('ExternalSigner', () => {
  it('forwards all 5 signing params to the callback', async () => {
    const signFn = vi.fn().mockResolvedValue('deadbeef');

    const signer = new ExternalSigner('02aabb', '1TestAddr', signFn);

    const txHex = 'cafebabe';
    const inputIndex = 0;
    const subscript = '76a914aabb88ac';
    const satoshis = 50000;
    const sigHashType = 0x41;

    const result = await signer.sign(txHex, inputIndex, subscript, satoshis, sigHashType);

    expect(result).toBe('deadbeef');
    expect(signFn).toHaveBeenCalledWith(txHex, inputIndex, subscript, satoshis, sigHashType);
  });

  it('forwards subscript and satoshis even without sigHashType', async () => {
    const signFn = vi.fn().mockResolvedValue('aabbccdd');

    const signer = new ExternalSigner('02aabb', '1TestAddr', signFn);

    await signer.sign('cafebabe', 1, '76a914', 100000);

    expect(signFn).toHaveBeenCalledWith('cafebabe', 1, '76a914', 100000, undefined);
  });

  it('returns pubkey and address from constructor', async () => {
    const signer = new ExternalSigner('02aabb', '1TestAddr', async () => '');
    expect(await signer.getPublicKey()).toBe('02aabb');
    expect(await signer.getAddress()).toBe('1TestAddr');
  });
});
