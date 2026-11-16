/**
 * R3-PY-NEGATIVES (TS part): a negative must prove the NODE refused the
 * spend, and why.
 *
 * The suite's negatives were bare `await expect(call).rejects.toThrow()`,
 * which passes on an SDK-side failure, an unreachable node, and -- since
 * GK-BUG-004 made a failed confirming mine an error -- an ACCEPTED tx whose
 * confirming mine failed. `expectNodeRejected` reads what each broadcast came
 * to instead (`instrumentBroadcast`'s `broadcastLog`).
 *
 * Drives the real SDK RPCProvider (through instrumentBroadcast) against a stub
 * JSON-RPC server on 127.0.0.1, so no node is needed. The project's
 * vitest.config.ts requires a live node via setup.ts; for a node-less run of
 * just this file point vitest at a config with no globalSetup, as for
 * helpers/compile.test.ts.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { createServer, type Server } from 'node:http';
import { AddressInfo, createServer as createNetServer } from 'node:net';
import { Transaction } from '@bsv/sdk';
import { RPCProvider } from 'runar-sdk';
import { instrumentBroadcast, expectNodeRejected, SCRIPT_VERIFY_FAILED } from './node.js';

const TXID = 'ab'.repeat(32);
const SCRIPT_FAILURE = 'mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)';
type Reply = [number, unknown];
const ok = (result: unknown): Reply => [200, { result, error: null, id: 'runar' }];
const err = (code: number, message: string): Reply => [500, { result: null, error: { code, message }, id: 'runar' }];

const servers: Server[] = [];
afterEach(() => { for (const s of servers.splice(0)) s.close(); });

async function stubNode(answers: Record<string, Reply>) {
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const method = (JSON.parse(body) as { method: string }).method;
      const [status, reply] = answers[method] ?? err(-32601, 'Method not found');
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(reply));
    });
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const { port } = server.address() as AddressInfo;
  return instrumentBroadcast(new RPCProvider(`http://127.0.0.1:${port}`, 'u', 'p', { autoMine: true }));
}

const broadcast = (p: RPCProvider) => p.broadcast(new Transaction());

/** The pre-R3 assertion: the call threw at all. */
async function oldShapeHolds(call: () => Promise<unknown>): Promise<boolean> {
  return call().then(() => false, () => true);
}

describe('expectNodeRejected', () => {
  it('an ACCEPTED tx whose confirming mine failed is not a rejection', async () => {
    const p = await stubNode({ sendrawtransaction: ok(TXID), generate: err(-32601, 'Method not found') });
    expect(await oldShapeHolds(() => broadcast(p))).toBe(true); // setup: the old assertion passes here
    await expect(expectNodeRejected(p, () => broadcast(p))).rejects.toThrow(/ACCEPTED/);
  });

  it('an accepted spend is not a rejection', async () => {
    const p = await stubNode({ sendrawtransaction: ok(TXID), generate: ok(['00']) });
    await expect(expectNodeRejected(p, () => broadcast(p))).rejects.toThrow(/ACCEPTED/);
  });

  it('an SDK-side refusal (nothing broadcast) is not a rejection', async () => {
    const p = await stubNode({});
    await expect(expectNodeRejected(p, () => Promise.reject(new Error('could not evaluate')))).rejects.toThrow(
      /never handed a transaction/,
    );
  });

  it('an unreachable node is not a rejection', async () => {
    const probe = createNetServer();
    await new Promise<void>((r) => probe.listen(0, '127.0.0.1', () => r()));
    const { port } = probe.address() as AddressInfo;
    await new Promise<void>((r) => probe.close(() => r()));
    const p = instrumentBroadcast(new RPCProvider(`http://127.0.0.1:${port}`, 'u', 'p', { autoMine: true }));
    await expect(expectNodeRejected(p, () => broadcast(p))).rejects.toThrow(/never ruled/);
  });

  it('a refusal for another reason is not the rejection under test', async () => {
    const p = await stubNode({ sendrawtransaction: err(-26, '16: bad-txns-inputs-missingorspent') });
    await expect(expectNodeRejected(p, () => broadcast(p))).rejects.toThrow(/wrong reason/);
  });

  it('control: a genuine script-verify refusal passes', async () => {
    const p = await stubNode({ sendrawtransaction: err(-26, SCRIPT_FAILURE) });
    await expectNodeRejected(p, () => broadcast(p), SCRIPT_VERIFY_FAILED);
    expect(p.broadcastLog).toEqual([{ kind: 'node-rejected', detail: SCRIPT_FAILURE }]);
  });
});
