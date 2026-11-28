import { describe, it } from 'vitest';
import { callChain, validateInput, stateOf, firstLine } from './harness.js';

/**
 * Variable-length state fields.
 *
 * `computeStateOutput` rebuilds the next UTXO's state section on-chain by
 * walking the current script's push-length prefixes (OP_SIZE / OP_SPLIT /
 * OP_CAT chains) and splicing in the new values. A ByteString state field
 * whose length crosses a push-encoding boundary (75 -> 76 bytes needs
 * OP_PUSHDATA1, 255 -> 256 needs OP_PUSHDATA2) changes the size of its *own
 * length prefix*, which shifts every offset the splice chain computed.
 */

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
}
`;

const bytesHex = (n: number) => 'ab'.repeat(n);

async function rewrite(initial: number, next: number) {
  const r = await callChain(NOTE, 'Note.runar.ts', [bytesHex(initial), 777n], { note: bytesHex(initial), amount: 777n }, [
    { method: 'set', args: [bytesHex(next)], signerKey: 'alice', callOptions: { satoshis: 100_000 } },
  ], { satoshis: 100_000 });
  const v = validateInput(r.txs[1]!, 0, r.txs[0]!, 0);
  const st = stateOf(r.artifact, r.txs[1]!) as any;
  const noteBack = typeof st?.note === 'string' ? st.note : '';
  return { v, st, ok: noteBack.toLowerCase() === bytesHex(next).toLowerCase(), noteLen: noteBack.length / 2 };
}

describe('variable-length state splice', () => {
  it('V1 rewrite a ByteString across every push-encoding boundary', async () => {
    // Annotated: an unannotated array literal of pairs infers number[][] under
    // noUncheckedIndexedAccess, so `from`/`to` arrive as number | undefined and
    // every use below needs a guard that the table already guarantees.
    const sizes: Array<[number, number]> = [
      [1, 1], [1, 75], [75, 76], [76, 75], [10, 200], [200, 10],
      [254, 255], [255, 256], [256, 255], [300, 40], [40, 300], [1, 520], [520, 1],
    ];
    for (const [from, to] of sizes) {
      try {
        const r = await rewrite(from, to);
        console.log(`V1 ${String(from).padStart(3)}B -> ${String(to).padStart(3)}B: covenant=${r.v.ok ? 'ACCEPT' : 'reject'} stateRoundTrips=${r.ok} (got ${r.noteLen}B) ${r.v.ok && !r.ok ? '*** MISMORPHED STATE ***' : ''} ${r.v.ok ? '' : '| ' + firstLine(r.v.error, 60)}`);
      } catch (e: any) {
        console.log(`V1 ${String(from).padStart(3)}B -> ${String(to).padStart(3)}B: threw ${firstLine(String(e.message), 110)}`);
      }
    }
  });

  it('V2 grow the note, then read the neighbouring bigint field back', async () => {
    // Two fields, one variable length followed by a fixed 8-byte word: if the
    // splice miscounts, the bigint behind it is what silently changes.
    const pairs: Array<[number, number]> = [[1, 76], [76, 1], [10, 300], [75, 76]];
    for (const [from, to] of pairs) {
      try {
        const r = await callChain(NOTE, 'Note.runar.ts', [bytesHex(from), 777n], { note: bytesHex(from), amount: 777n }, [
          { method: 'set', args: [bytesHex(to)], signerKey: 'alice', callOptions: { satoshis: 100_000 } },
          { method: 'bump', args: [778n], signerKey: 'alice', callOptions: { satoshis: 100_000 } },
        ], { satoshis: 100_000 });
        const v1 = validateInput(r.txs[1]!, 0, r.txs[0]!, 0);
        const v2 = validateInput(r.txs[2]!, 0, r.txs[1]!, 0);
        const st = stateOf(r.artifact, r.txs[2]!) as any;
        console.log(`V2 note ${from}B -> ${to}B then bump: step1=${v1.ok ? 'ACCEPT' : 'reject'} step2=${v2.ok ? 'ACCEPT' : 'reject'} amount after bump=${st?.amount} ${v2.ok && String(st?.amount) !== '778' ? '*** WRONG VALUE ***' : ''}`);
      } catch (e: any) {
        console.log(`V2 note ${from}B -> ${to}B: threw ${firstLine(String(e.message), 100)}`);
      }
    }
  });
});
