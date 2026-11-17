import { describe, it, expect, vi, afterEach } from 'vitest';
import { RPCProvider, RPCNodeError } from '../index.js';

// R3-PY-NEGATIVES (TS part): RPCProvider reports the node's JSON-RPC error as a
// typed RPCNodeError (method, code, node message), so a caller can tell "the
// node said no" from "the node never answered" without parsing message text.
// SV Node answers an error with HTTP 500 and the error object in the body.

const REFUSAL = { code: -26, message: 'mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)' };

function stubFetch(status: number, body: unknown) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(body), { status })));
}

afterEach(() => vi.unstubAllGlobals());

describe('RPCProvider node errors', () => {
  for (const status of [500, 200]) {
    it(`a JSON-RPC error reply (HTTP ${status}) is an RPCNodeError carrying method, code and message`, async () => {
      stubFetch(status, { result: null, error: REFUSAL, id: 'runar' });
      const p = new RPCProvider('http://127.0.0.1:1', 'u', 'p');
      const err = await p.getRawTransaction('ab'.repeat(32)).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RPCNodeError);
      const e = err as RPCNodeError;
      expect(e.method).toBe('getrawtransaction');
      expect(e.code).toBe(-26);
      expect(e.nodeMessage).toBe(REFUSAL.message);
      expect(e.message).toBe(`RPC getrawtransaction: ${REFUSAL.message}`);
      expect(e).toBeInstanceOf(Error);
    });
  }

  it('a transport failure is not an RPCNodeError', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('fetch failed'); }));
    const p = new RPCProvider('http://127.0.0.1:1', 'u', 'p');
    const err = await p.getRawTransaction('ab'.repeat(32)).catch((e: unknown) => e);
    expect(err).not.toBeInstanceOf(RPCNodeError);
  });
});
