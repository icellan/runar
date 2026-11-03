// F-027: GorillaPoolProvider.getTransaction must report each output's exact
// satoshis. GorillaPool's GET /tx/{txid} is binary (not the JSON `vout[].value`
// the old decoder, with its `< 1000 → BTC` guess, expected), so the provider
// fetches GET /tx/{txid}/raw and reads the 8-byte LE amount from the raw tx.
//
// Proves: with the shared recorded responses (conformance/sdk-gorillapool),
// a real 1-sat inscription output decodes to 1 sat, 999/1000/1e12/2.1e15 are
// exact, the input/output shape matches, and a body that hashes to a different
// txid is rejected. Does NOT prove the live API still serves /tx/{txid}/raw
// (vectors recorded 2026-09-27).
import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { GorillaPoolProvider } from '../providers/gorillapool.js';

interface GpVector {
  name: string;
  txid: string;
  responseHex: string;
  expected: {
    version: number;
    locktime: number;
    inputCount: number;
    firstInput: { txid: string; outputIndex: number; scriptLen: number; scriptSha256: string; sequence: number };
    outputs: { satoshis: number; scriptLen: number; scriptSha256: string }[];
  };
}
interface GpVectorFile {
  vectors: GpVector[];
  rejection_vectors: { name: string; requestedTxid: string; responseOf: string }[];
}

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(here, '..', '..', '..', '..', 'conformance', 'sdk-gorillapool', 'vectors.json'), 'utf8'),
) as GpVectorFile;

const sha256Hex = (hex: string) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');

/** Serve `bodyHex` (decoded to bytes) at `${base}/tx/${txid}/raw`; 404 elsewhere. */
function serveRaw(txid: string, bodyHex: string) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url === `https://ordinals.gorillapool.io/api/tx/${txid}/raw`) {
      return new Response(Buffer.from(bodyHex, 'hex'), { status: 200 });
    }
    return new Response('{"message":"Not Found"}', { status: 404 });
  });
}

afterEach(() => vi.restoreAllMocks());

describe('F-027 GorillaPoolProvider.getTransaction decodes the real raw tx', () => {
  it('loads the shared vectors', () => {
    expect(vectors.vectors.length).toBeGreaterThanOrEqual(3);
  });

  for (const v of vectors.vectors) {
    it(`${v.name}: satoshis ${v.expected.outputs.map((o) => o.satoshis).join(', ')}`, async () => {
      serveRaw(v.txid, v.responseHex);
      const data = await new GorillaPoolProvider('mainnet').getTransaction(v.txid);

      expect(data.txid).toBe(v.txid);
      expect(data.version).toBe(v.expected.version);
      expect(data.locktime).toBe(v.expected.locktime);
      expect(data.raw).toBe(v.responseHex);
      expect(data.inputs).toHaveLength(v.expected.inputCount);
      const in0 = data.inputs[0]!;
      expect(in0.txid).toBe(v.expected.firstInput.txid);
      expect(in0.outputIndex).toBe(v.expected.firstInput.outputIndex);
      expect(in0.sequence).toBe(v.expected.firstInput.sequence);
      expect(in0.script.length).toBe(2 * v.expected.firstInput.scriptLen);
      expect(sha256Hex(in0.script)).toBe(v.expected.firstInput.scriptSha256);
      expect(data.outputs.map((o) => o.satoshis)).toEqual(v.expected.outputs.map((o) => o.satoshis));
      data.outputs.forEach((o, i) => {
        expect(o.script.length).toBe(2 * v.expected.outputs[i]!.scriptLen);
        expect(sha256Hex(o.script)).toBe(v.expected.outputs[i]!.scriptSha256);
      });
    });
  }

  for (const rv of vectors.rejection_vectors) {
    it(`rejects ${rv.name}`, async () => {
      const src = vectors.vectors.find((v) => v.name === rv.responseOf)!;
      serveRaw(rv.requestedTxid, src.responseHex);
      await expect(new GorillaPoolProvider('mainnet').getTransaction(rv.requestedTxid)).rejects.toThrow(/txid mismatch/);
    });
  }
});
