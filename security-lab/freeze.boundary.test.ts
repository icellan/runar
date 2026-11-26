import { describe, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { callChain, validateInput, key } from './harness.js';

const BOARD = 'examples/ts/message-board/MessageBoard.runar.ts';
const boardSource = readFileSync(BOARD, 'utf8');
const msg = (n: number) => 'ab'.repeat(n);

describe('exact frozen window', () => {
  it('store N bytes, then spend again — per-length verdicts', async () => {
    for (const len of [120, 124, 125, 126, 127, 128, 129, 130, 200, 250, 254, 255, 256]) {
      let store = '?';
      let next = '?';
      let stateHex = '';
      try {
        const r = await callChain(boardSource, BOARD, [msg(4), key('alice').pubKey], { message: msg(4), owner: key('alice').pubKey }, [
          { method: 'post', args: [msg(len)], signerKey: 'bob' },
        ], { satoshis: 500_000 }, 2_000_000);
        store = validateInput(r.txs[1]!, 0, r.txs[0]!, 0).ok ? 'ok' : 'REJECTED';
        const full = r.txs[1]!.outputs[0]!.lockingScript.toHex();
        stateHex = full.slice(full.length - (len * 2 + 4));
      } catch (e: any) {
        store = 'threw:' + (String(e.message).match(/Script evaluation error: [^\n]*/)?.[0] ?? String(e.message)).slice(0, 40);
      }
      try {
        const r2 = await callChain(boardSource, BOARD, [msg(len), key('alice').pubKey], { message: msg(len), owner: key('alice').pubKey }, [
          { method: 'post', args: [msg(4)], signerKey: 'bob' },
        ], { satoshis: 500_000 }, 2_000_000);
        next = validateInput(r2.txs[1]!, 0, r2.txs[0]!, 0).ok ? 'ok' : 'FROZEN';
      } catch (e: any) {
        next = 'FROZEN(' + (String(e.message).match(/Script evaluation error: [^\n]*/)?.[0] ?? '').replace('Script evaluation error: ', '').slice(0, 45) + ')';
      }
      console.log(`  len=${String(len).padStart(3)} | store=${store.padEnd(12)} | next spend from it=${next} | prefix bytes: ${stateHex.slice(0, 8)}`);
    }
  });
});
