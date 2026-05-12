// ---------------------------------------------------------------------------
// Tests for runar-sdk/signers/mock.ts — deterministic mock signer
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { MockSigner } from '../signers/mock.js';
import type { Signer } from '../signers/signer.js';
// Confirm the SDK barrel re-exports MockSigner so external callers can use it.
import { MockSigner as MockSignerFromBarrel } from '../index.js';

describe('MockSigner', () => {
  it('is exported from the SDK top-level barrel', () => {
    expect(MockSignerFromBarrel).toBe(MockSigner);
  });

  it('returns the default 33-byte compressed pubkey when no constructor args supplied', async () => {
    const signer: Signer = new MockSigner();
    const pk = await signer.getPublicKey();
    expect(pk).toBe('02' + '00'.repeat(32));
    expect(pk.length).toBe(66);
  });

  it('returns the default 20-byte mock address when no constructor args supplied', async () => {
    const signer = new MockSigner();
    const addr = await signer.getAddress();
    expect(addr).toBe('00'.repeat(20));
    expect(addr.length).toBe(40);
  });

  it('returns deterministic pubkey across many calls', async () => {
    const signer = new MockSigner();
    const first = await signer.getPublicKey();
    for (let i = 0; i < 10; i++) {
      expect(await signer.getPublicKey()).toBe(first);
    }
  });

  it('returns deterministic 72-byte DER-shaped signature ending with the default sighash byte 0x41', async () => {
    const signer = new MockSigner();
    const sig = await signer.sign('aabbcc', 0, '76a914' + '00'.repeat(20) + '88ac', 1000);
    // 0x30 prefix + 70 zero bytes + 0x41 sighash = 144 hex chars
    expect(sig.length).toBe(144);
    expect(sig.startsWith('30')).toBe(true);
    expect(sig.endsWith('41')).toBe(true);
    expect(sig.slice(2, -2)).toBe('00'.repeat(70));
  });

  it('produces the SAME signature byte-for-byte across repeated calls with different tx data', async () => {
    const signer = new MockSigner();
    const a = await signer.sign('00', 0, '00', 1);
    const b = await signer.sign('ffeeddcc', 7, 'ababab', 999_999);
    const c = await signer.sign('aabb', 3, '76a914' + '11'.repeat(20) + '88ac', 12345);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('honors a non-default sighash type by encoding it as the trailing byte', async () => {
    const signer = new MockSigner();
    const sig = await signer.sign('aa', 0, '00', 1, 0x42);
    expect(sig.endsWith('42')).toBe(true);
    expect(sig.length).toBe(144);
  });

  it('accepts a custom pubkey hex', async () => {
    const customPk = '03' + 'ab'.repeat(32);
    const signer = new MockSigner(customPk);
    expect(await signer.getPublicKey()).toBe(customPk);
    // Address still defaults
    expect(await signer.getAddress()).toBe('00'.repeat(20));
  });

  it('accepts a custom address', async () => {
    const customAddr = 'ff'.repeat(20);
    const signer = new MockSigner(undefined, customAddr);
    expect(await signer.getAddress()).toBe(customAddr);
    expect(await signer.getPublicKey()).toBe('02' + '00'.repeat(32));
  });

  it('two distinct MockSigner instances with default args produce identical outputs', async () => {
    const a = new MockSigner();
    const b = new MockSigner();
    expect(await a.getPublicKey()).toBe(await b.getPublicKey());
    expect(await a.getAddress()).toBe(await b.getAddress());
    expect(await a.sign('00', 0, '00', 0)).toBe(await b.sign('ff', 1, 'ab', 99));
  });
});
