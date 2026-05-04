// ---------------------------------------------------------------------------
// wallet-client.spec.ts — live BRC-100 WalletClient integration test
// ---------------------------------------------------------------------------
//
// Mirrors integration/ruby/spec/wallet_client_spec.rb. Environment-gated:
// runs only when RUNAR_WALLET_ENDPOINT is set to the base URL of a BRC-100
// JSON-over-HTTP wallet endpoint. When unset, the test is skipped cleanly so
// local + CI runs stay green without any wallet setup.
//
// Optional env:
//   RUNAR_WALLET_ENDPOINT — base URL, required
//   RUNAR_WALLET_AUTH     — bearer token, optional
//   RUNAR_WALLET_BASKET   — basket name, default 'runar-integration-test'
//
// Asserts:
//   * getPublicKey returns a 33-byte (66 hex char) compressed pubkey
//     prefixed 02/03.
//   * listOutputs returns an array of output descriptors; if non-empty,
//     each entry exposes outpoint / satoshis / lockingScript shape.
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { WalletClient, HTTPWalletJSON, type SecurityLevel } from '@bsv/sdk';

const ENDPOINT = process.env.RUNAR_WALLET_ENDPOINT;
const AUTH_TOKEN = process.env.RUNAR_WALLET_AUTH;
const BASKET = process.env.RUNAR_WALLET_BASKET ?? 'runar-integration-test';

const PROTOCOL_ID: [SecurityLevel, string] = [2 as SecurityLevel, 'runar integration'];
const KEY_ID = '1';

function buildClient(endpoint: string): WalletClient {
  // If an auth token is provided, wire it through a custom fetch wrapper.
  const customFetch: typeof fetch | undefined = AUTH_TOKEN
    ? (input, init) => {
        const headers = new Headers(init?.headers);
        headers.set('Authorization', `Bearer ${AUTH_TOKEN}`);
        return fetch(input, { ...init, headers });
      }
    : undefined;
  const substrate = new HTTPWalletJSON(undefined, endpoint, customFetch);
  return new WalletClient(substrate);
}

const COMPRESSED_PUBKEY_HEX = /^[0-9a-fA-F]{66}$/;

describe.skipIf(!ENDPOINT)('BRC-100 WalletClient live endpoint', () => {
  it('performs a minimal round-trip (getPublicKey + listOutputs)', async () => {
    const wallet = buildClient(ENDPOINT!);

    // 1. getPublicKey: must return a 33-byte compressed secp256k1 key.
    const { publicKey } = await wallet.getPublicKey({
      protocolID: PROTOCOL_ID,
      keyID: KEY_ID,
    });
    expect(typeof publicKey).toBe('string');
    expect(publicKey).toMatch(COMPRESSED_PUBKEY_HEX);
    expect(['02', '03']).toContain(publicKey.slice(0, 2));

    // 2. listOutputs: must return an array (possibly empty).
    const result = await wallet.listOutputs({ basket: BASKET, limit: 10 });
    expect(result).toBeTypeOf('object');
    expect(Array.isArray(result.outputs)).toBe(true);
    for (const out of result.outputs) {
      expect(out).toBeTypeOf('object');
      // Canonical BRC-100 ListOutputsResult fields: outpoint + satoshis,
      // optional lockingScript.
      const keys = Object.keys(out);
      expect(keys.includes('outpoint') || keys.includes('satoshis') || keys.includes('lockingScript')).toBe(true);
    }
  }, 60_000);
});

// Provide a sentinel test so the file is non-empty when the suite is skipped,
// and shows up in vitest output as discovered-but-skipped rather than empty.
describe.skipIf(ENDPOINT)('BRC-100 WalletClient live endpoint (skipped)', () => {
  it.skip('RUNAR_WALLET_ENDPOINT not set — set it to a BRC-100 wallet URL to enable', () => {
    /* placeholder */
  });
});
