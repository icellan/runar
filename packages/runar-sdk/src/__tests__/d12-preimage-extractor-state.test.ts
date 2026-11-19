/**
 * D12 D2 (PRE-P2-1): when a stateful method writes a preimage field into
 * state, the SDK ANF interpreter must derive it from the transaction being
 * built, not from a dummy. It used to answer extractLocktime = 0,
 * extractSequence = 0xfffffffe and extractOutpoint = 36 zero bytes, while the
 * real tx carries nLockTime = options.locktime, nSequence 0xffffffff by
 * default, and the real spent outpoint, so the SDK built a continuation the
 * covenant refused.
 *
 * Proves (MockProvider replays every input on @bsv/sdk Spend): a call whose
 * state takes locktime / sequence / outpoint from the preimage is accepted,
 * and the committed state equals the real tx's fields.
 * Does not prove: other tiers.
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';

const SRC = `import { StatefulSmartContract, ByteString, extractLocktime, extractSequence, extractOutpoint } from 'runar-lang';

class Rec extends StatefulSmartContract {
  lt: bigint;
  sq: bigint;
  op: ByteString;
  constructor(lt: bigint, sq: bigint, op: ByteString) { super(lt, sq, op); this.lt = lt; this.sq = sq; this.op = op; }
  public record() {
    this.lt = extractLocktime(this.txPreimage);
    this.sq = extractSequence(this.txPreimage);
    this.op = extractOutpoint(this.txPreimage);
  }
}
`;

async function setup() {
  const r = compile(SRC, { fileName: 'Rec.runar.ts' });
  if (!r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  const signer = new LocalSigner('11'.repeat(32));
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 5_000_000,
    script: buildP2PKHScript(await signer.getPublicKey()),
  });
  const c = new RunarContract(r.artifact, [0n, 0n, '00']);
  c.connect(provider, signer);
  await c.deploy({ satoshis: 50_000 });
  return c;
}

const wireOutpoint = (txid: string, vout: number) =>
  txid.match(/../g)!.reverse().join('') + vout.toString(16).padStart(8, '0').match(/../g)!.reverse().join('');

describe('D12 D2: preimage extractors read the tx being built', () => {
  it('default options: locktime 0, sequence 0xffffffff, real outpoint', async () => {
    const c = await setup();
    const spent = c.getUtxo()!;
    await c.call('record', []);
    expect(c.state).toEqual({ lt: 0n, sq: 0xffffffffn, op: wireOutpoint(spent.txid, spent.outputIndex) });
  });

  it('explicit locktime: sequence defaults to 0xfffffffe', async () => {
    const c = await setup();
    const spent = c.getUtxo()!;
    await c.call('record', [], { locktime: 1234 });
    expect(c.state).toEqual({ lt: 1234n, sq: 0xfffffffen, op: wireOutpoint(spent.txid, spent.outputIndex) });
  });

  it('explicit sequence', async () => {
    const c = await setup();
    await c.call('record', [], { locktime: 10, sequence: 7 });
    expect(c.state).toMatchObject({ lt: 10n, sq: 7n });
  });
});
