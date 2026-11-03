// N-041: WhatsOnChainProvider.getContractUtxo returned `script: ''` (WoC's
// /script/{h}/unspent listing carries no locking script), and getTransaction
// read GET /tx/hash/{txid}, whose JSON has no `hex` field, so `raw` was
// always empty and satoshis came from float BTC values. ExternalSigner passed
// an empty subscript straight to its callback.
//
// Proves, with the shared vectors in
// conformance/sdk-woc/contract-utxo-tx-vectors.json and a stubbed fetch:
//   - getContractUtxo returns the real locking script of the listed outpoint
//     for both the legacy array and the {script,result} object listing, and
//     returns null for an empty listing or a 404;
//   - it fails loudly on a txid mismatch, a missing output, a value mismatch,
//     an output whose script does not hash to the requested scripthash, an
//     empty script, and an unavailable raw tx;
//   - getTransaction returns the served hex as `raw`, hash-verified, with
//     inputs/outputs parsed from it and integer satoshis exact at 21e14 scale;
//     a body that hashes to another txid is refused;
//   - ExternalSigner refuses an empty subscript without invoking the callback;
//   - computeOpPushTx refuses an empty subscript.
// Does NOT prove: that the live WoC API keeps these shapes (recorded
// 2026-09-29), nor which of several listed UTXOs is the "right" contract UTXO
// (the first entry is used, as before), nor anything about a non-empty
// subscript whose codeSeparatorIndex is its last byte (still not refused).
import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { WhatsOnChainProvider } from '../providers/woc.js';
import { ExternalSigner } from '../signers/external.js';
import { computeOpPushTx } from '../oppushtx.js';

interface Vectors {
  contractUtxo: {
    scriptHash: string;
    legacyBody: string;
    objectBody: string;
    rawTxHex: Record<string, string>;
    expectedLegacy: unknown;
    expectedObject: unknown;
    null_vectors: { name: string; body: string | null }[];
    rejection_vectors: {
      name: string;
      scriptHash: string;
      body: string;
      rawTxHex: Record<string, string>;
      error: string;
    }[];
  };
  getTransaction: {
    cases: { name: string; txid: string; rawTxHex: string; hashBody: string; expected: unknown }[];
    rejection_vectors: {
      name: string;
      txid: string;
      rawTxHex: string | null;
      hashBody: string | null;
      error: string;
    }[];
  };
}

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(
    join(here, '..', '..', '..', '..', 'conformance', 'sdk-woc', 'contract-utxo-tx-vectors.json'),
    'utf8',
  ),
) as Vectors;

const BASE = 'https://api.whatsonchain.com/v1/bsv/main';

/** Serve exact paths from `routes`; everything else is a 404. */
function serve(routes: Record<string, string>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input);
    if (url.startsWith(BASE) && routes[url.slice(BASE.length)] !== undefined) {
      return new Response(routes[url.slice(BASE.length)], { status: 200 });
    }
    return new Response('Not Found', { status: 404 });
  });
}

function rawRoutes(rawTxHex: Record<string, string>): Record<string, string> {
  const r: Record<string, string> = {};
  for (const [txid, hex] of Object.entries(rawTxHex)) r[`/tx/${txid}/hex`] = hex;
  return r;
}

afterEach(() => vi.restoreAllMocks());

describe('N-041 WhatsOnChainProvider.getContractUtxo returns the real locking script', () => {
  const cu = vectors.contractUtxo;

  it('legacy array listing', async () => {
    serve({ [`/script/${cu.scriptHash}/unspent`]: cu.legacyBody, ...rawRoutes(cu.rawTxHex) });
    const utxo = await new WhatsOnChainProvider('mainnet').getContractUtxo(cu.scriptHash);
    expect(utxo).toEqual(cu.expectedLegacy);
  });

  it('object {script,result} listing', async () => {
    serve({ [`/script/${cu.scriptHash}/unspent`]: cu.objectBody, ...rawRoutes(cu.rawTxHex) });
    const utxo = await new WhatsOnChainProvider('mainnet').getContractUtxo(cu.scriptHash);
    expect(utxo).toEqual(cu.expectedObject);
  });

  for (const nv of cu.null_vectors) {
    it(`returns null for ${nv.name}`, async () => {
      serve(nv.body === null ? {} : { [`/script/${cu.scriptHash}/unspent`]: nv.body });
      expect(await new WhatsOnChainProvider('mainnet').getContractUtxo(cu.scriptHash)).toBeNull();
    });
  }

  for (const rv of cu.rejection_vectors) {
    it(`rejects ${rv.name}`, async () => {
      serve({ [`/script/${rv.scriptHash}/unspent`]: rv.body, ...rawRoutes(rv.rawTxHex) });
      await expect(
        new WhatsOnChainProvider('mainnet').getContractUtxo(rv.scriptHash),
      ).rejects.toThrow(rv.error);
    });
  }
});

describe('N-041 WhatsOnChainProvider.getTransaction parses the hash-verified raw tx', () => {
  for (const c of vectors.getTransaction.cases) {
    it(`${c.name}: raw present, satoshis exact`, async () => {
      serve({ [`/tx/${c.txid}/hex`]: c.rawTxHex, [`/tx/hash/${c.txid}`]: c.hashBody });
      const tx = await new WhatsOnChainProvider('mainnet').getTransaction(c.txid);
      expect(tx).toEqual(c.expected);
    });
  }

  for (const rv of vectors.getTransaction.rejection_vectors) {
    it(`rejects ${rv.name}`, async () => {
      const routes: Record<string, string> = {};
      if (rv.rawTxHex !== null) routes[`/tx/${rv.txid}/hex`] = rv.rawTxHex;
      if (rv.hashBody !== null) routes[`/tx/hash/${rv.txid}`] = rv.hashBody;
      serve(routes);
      await expect(new WhatsOnChainProvider('mainnet').getTransaction(rv.txid)).rejects.toThrow(
        rv.error,
      );
    });
  }
});

describe('N-041 ExternalSigner refuses an empty subscript', () => {
  it('throws before invoking the callback', async () => {
    const cb = vi.fn(async () => 'deadbeef');
    const signer = new ExternalSigner('02'.repeat(33), 'addr', cb);
    await expect(signer.sign('00', 0, '', 1000)).rejects.toThrow(/empty subscript/);
    expect(cb).not.toHaveBeenCalled();
  });

  it('still delegates a non-empty subscript', async () => {
    const cb = vi.fn(async () => 'deadbeef');
    const signer = new ExternalSigner('02'.repeat(33), 'addr', cb);
    expect(await signer.sign('00', 0, '51', 1000)).toBe('deadbeef');
    expect(cb).toHaveBeenCalledOnce();
  });
});

describe('N-041 computeOpPushTx refuses an empty subscript', () => {
  // 1-in/1-out tx spending 11..11:0.
  const txHex =
    '01000000' + '01' + '11'.repeat(32) + '00000000' + '00' + 'ffffffff' +
    '01' + '8403000000000000' + '01' + '51' + '00000000';

  it('empty subscript', () => {
    expect(() => computeOpPushTx(txHex, 0, '', 1000)).toThrow(/empty subscript/);
  });

  it('a non-empty scriptCode still works', () => {
    expect(computeOpPushTx(txHex, 0, '51ab51', 1000, 1).preimageHex.length).toBeGreaterThan(0);
  });
});
