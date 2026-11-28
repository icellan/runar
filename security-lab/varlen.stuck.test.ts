import { describe, it } from 'vitest';
import { callChain, validateInput, build, asm, firstLine } from './harness.js';

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
  public bump(v: bigint) {
    this.amount = v;
  }
  public noop() {
    this.amount = this.amount;
  }
}
`;
const hex = (n: number, fill = 'ab') => fill.repeat(n);

async function spend(initialBytes: number, method: 'set' | 'bump' | 'noop', args: unknown[], fill = 'ab') {
  try {
    const r = await callChain(NOTE, 'Note.runar.ts', [hex(initialBytes, fill), 777n], { note: hex(initialBytes, fill), amount: 777n }, [
      { method, args, signerKey: 'alice', callOptions: { satoshis: 100_000 } },
    ], { satoshis: 100_000 });
    const v = validateInput(r.txs[1]!, 0, r.txs[0]!, 0);
    return { ok: v.ok, err: v.error };
  } catch (e: any) {
    const msg = String(e.message);
    const m = msg.match(/Script evaluation error: [^\n]*/);
    return { ok: false, err: (m?.[0] ?? firstLine(msg)).slice(0, 100) };
  }
}

describe('a 76..255 byte ByteString state field freezes the UTXO', () => {
  it('S1 any method, any new value, once the stored blob is in the OP_PUSHDATA1 range', async () => {
    for (const size of [75, 76, 100, 200, 255, 256, 300]) {
      const noop = await spend(size, 'noop', []);
      const bump = await spend(size, 'bump', [778n]);
      const same = await spend(size, 'set', [hex(size)]);
      console.log(`stored=${String(size).padStart(3)}B | noop: ${noop.ok ? 'ok' : 'FROZEN'} | bump(bigint only): ${bump.ok ? 'ok' : 'FROZEN'} | rewrite same length: ${same.ok ? 'ok' : 'FROZEN'}`);
    }
  });

  it('S2 is it the length, or the byte values?', async () => {
    for (const [fill, label] of [['ab', '0xab'], ['00', '0x00'], ['41', '0x41'], ['ff', '0xff']] as Array<[string, string]>) {
      const r76 = await spend(76, 'noop', [], fill);
      const r200 = await spend(200, 'noop', [], fill);
      console.log(`fill=${label}: 76B -> ${r76.ok ? 'ok' : 'FROZEN'}, 200B -> ${r200.ok ? 'ok' : 'FROZEN'}`);
    }
  });

  it('S3 the scan loop the covenant runs', () => {
    const c = build(NOTE, 'Note.runar.ts', { note: 'ab'.repeat(4), amount: 777n });
    const s = asm(c.scriptHex);
    // Show the tail of the state-scan machinery used by every method branch.
    const tail = s.slice(-1400);
    console.log('script tail:\n ', tail.replace(/ (OP_1 OP_SPLIT OP_ROT OP_ROT OP_SWAP OP_CAT)/g, '$1'));
  });
});
