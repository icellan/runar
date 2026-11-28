import { describe, it } from 'vitest';
import { callChain, validateInput, stateOf } from './harness.js';

const NOTE = `
class Note extends StatefulSmartContract {
  note: ByteString;
  amount: bigint;
  constructor(note: ByteString, amount: bigint) {
    super(note, amount);
    this.note = note;
    this.amount = amount;
  }
  public set(n: ByteString) {
    this.note = n;
  }
}
`;
const bytesHex = (n: number) => 'ab'.repeat(n);

async function attempt(from: number, to: number) {
  try {
    const r = await callChain(NOTE, 'Note.runar.ts', [bytesHex(from), 777n], { note: bytesHex(from), amount: 777n }, [
      { method: 'set', args: [bytesHex(to)], signerKey: 'alice', callOptions: { satoshis: 100_000 } },
    ], { satoshis: 100_000 });
    const v = validateInput(r.txs[1]!, 0, r.txs[0]!, 0);
    const st = stateOf(r.artifact, r.txs[1]!) as any;
    return { ok: v.ok && String(st?.note).toLowerCase() === bytesHex(to).toLowerCase(), err: v.error };
  } catch (e: any) {
    const msg = String(e.message);
    const m = msg.match(/Script evaluation error: [^\n]*/);
    return { ok: false, err: m ? m[0] : msg.split('\n')[0] };
  }
}

describe('state splice boundary map', () => {
  it('shrinking across the 75/76 and 255/256 push boundaries', async () => {
    const grid = [1, 10, 74, 75, 76, 77, 100, 200, 253, 254, 255, 256, 257, 300, 520];
    const bad: string[] = [];
    for (const from of grid) {
      const row: string[] = [];
      for (const to of grid) {
        const r = await attempt(from, to);
        row.push(r.ok ? '.' : 'X');
        if (!r.ok) bad.push(`${from}->${to}: ${(r.err ?? '').slice(0, 70)}`);
      }
      console.log(`from ${String(from).padStart(3)} | ${row.join(' ')}`);
    }
    console.log('grid header    :', grid.map((g) => String(g).padStart(1)).join(' '));
    console.log('\nfailures:');
    for (const b of bad) console.log('  ', b);
  });
});
