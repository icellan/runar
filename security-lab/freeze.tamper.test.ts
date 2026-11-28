import { describe, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { callChain, validateInput, key, firstLine } from './harness.js';

const BOARD = 'examples/ts/message-board/MessageBoard.runar.ts';
const boardSource = readFileSync(BOARD, 'utf8');
const msg = (n: number) => 'ab'.repeat(n);

describe('is verification still sound just below the freeze window?', () => {
  it('tamper the continuation state at lengths 4 / 128 / 200', async () => {
    for (const len of [4, 75, 127, 128, 129, 200]) {
      let honest = '?';
      let tampered = '?';
      try {
        const r = await callChain(boardSource, BOARD, [msg(len), key('alice').pubKey], { message: msg(len), owner: key('alice').pubKey }, [
          { method: 'post', args: [msg(len)], signerKey: 'bob' },
        ], { satoshis: 500_000 }, 2_000_000);
        honest = validateInput(r.txs[1]!, 0, r.txs[0]!, 0).ok ? 'accepted' : 'REJECTED';
        // (An earlier case flipped a byte inside the continuation script. Hand-
        // rebuilding the script's chunks was fiddlier and less honest about what
        // had actually been tampered with, so every case here changes the
        // continuation output's *amount* — the value the covenant must defend.)
        const flipAmount = (tx: any) => { tx.outputs[0].satoshis = (tx.outputs[0].satoshis ?? 0) - 1; };
        const t = validateInput(r.txs[1]!, 0, r.txs[0]!, 0, flipAmount);
        tampered = t.ok ? '*** ACCEPTED THOUGH TAMPERED ***' : 'rejected (good)';
      } catch (e: any) {
        const m = String(e.message).match(/Script evaluation error: [^\n]*/)?.[0];
        const v = m ?? String(e.message).split('\n')[0];
        if (honest === '?') honest = 'threw: ' + firstLine(v, 50);
        tampered = 'n/a';
      }
      console.log(`  stored ${String(len).padStart(3)} bytes: honest=${honest} | amount-tampered=${tampered}`);
    }
  });
});
