// N-025: GorillaPoolProvider must call the routes the GorillaPool API actually
// serves, decode their documented shapes, and surface a 404 as an error. The
// old routes (/tx/{txid}/hex, /address/{a}/utxos, /script/{h}/utxos,
// /inscriptions/address/{a}, /bsv20/balance/..., /bsv20/utxos/...) do not
// exist, and the provider mapped their 404 to [] / null / '0'.
//
// Proves: replaying the shared recorded responses
// (conformance/sdk-gorillapool/endpoint-vectors.json, recorded 2026-10-05),
// every call decodes to the independently derived expectation, every
// unrouted (404) request raises, tampered bodies (txid mismatch, listing value
// != raw tx value, inscription content not matching its hash) are refused,
// getContractUtxo refuses (no documented route), and broadcast posts
// {"rawtx": hex}.
// Does NOT prove: that the live API still serves these shapes; that POST
// /api/tx accepts {"rawtx"} (schema-documented, never sent live); pagination
// beyond the API's default page (100).
import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Transaction } from '@bsv/sdk';
import { GorillaPoolProvider } from '../providers/gorillapool.js';

interface Route { method: string; path: string; status: number; contentType: string; bodyHex: string }
interface Call { call: string; args: string[]; expect?: unknown; expectError?: string; expectRequestJson?: unknown }
interface VectorFile { notFound: Route; routes: Route[]; calls: Call[] }

const here = dirname(fileURLToPath(import.meta.url));
const vf = JSON.parse(
  readFileSync(join(here, '..', '..', '..', '..', 'conformance', 'sdk-gorillapool', 'endpoint-vectors.json'), 'utf8'),
) as VectorFile;

const HOST = 'https://ordinals.gorillapool.io';

/** Serve the recorded routes; anything else gets the recorded 404. Returns the POST bodies seen. */
function serve(): { posted: string[] } {
  const posted: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    const method = (init?.method ?? 'GET').toUpperCase();
    if (method === 'POST' && typeof init?.body === 'string') posted.push(init.body);
    const r = vf.routes.find((x) => x.method === method && HOST + x.path === url) ?? vf.notFound;
    return new Response(Buffer.from(r.bodyHex, 'hex'), {
      status: r.status,
      headers: r.contentType ? { 'content-type': r.contentType } : {},
    });
  });
  return { posted };
}

afterEach(() => vi.restoreAllMocks());

async function invoke(p: GorillaPoolProvider, c: Call): Promise<unknown> {
  switch (c.call) {
    case 'getRawTransaction': return p.getRawTransaction(c.args[0]!);
    case 'getUtxos': return p.getUtxos(c.args[0]!);
    case 'getContractUtxo': return p.getContractUtxo(c.args[0]!);
    case 'getInscriptionsByAddress': return p.getInscriptionsByAddress(c.args[0]!);
    case 'getInscription': return p.getInscription(c.args[0]!);
    case 'getBSV20Balance': return p.getBSV20Balance(c.args[0]!, c.args[1]!);
    case 'getBSV21Balance': return p.getBSV21Balance(c.args[0]!, c.args[1]!);
    case 'getBSV20Utxos': return p.getBSV20Utxos(c.args[0]!, c.args[1]!);
    case 'getBSV21Utxos': return p.getBSV21Utxos(c.args[0]!, c.args[1]!);
    case 'broadcast': return p.broadcast(Transaction.fromHex(c.args[0]!));
    default: throw new Error(`unknown call ${c.call}`);
  }
}

describe('N-025 GorillaPoolProvider replays the recorded documented endpoints', () => {
  it('loads the shared vectors', () => {
    expect(vf.calls.length).toBeGreaterThanOrEqual(27);
  });

  vf.calls.forEach((c, i) => {
    const label = `#${i} ${c.call}(${c.args.map((a) => a.slice(0, 16)).join(', ')}) -> ${c.expectError ? `error /${c.expectError}/` : 'value'}`;
    it(label, async () => {
      const { posted } = serve();
      const p = new GorillaPoolProvider('mainnet');
      if (c.expectError !== undefined) {
        await expect(invoke(p, c)).rejects.toThrow(c.expectError);
      } else {
        expect(await invoke(p, c)).toEqual(c.expect);
      }
      if (c.expectRequestJson !== undefined) {
        expect(posted).toHaveLength(1);
        expect(JSON.parse(posted[0]!)).toEqual(c.expectRequestJson);
      }
    });
  });
});
