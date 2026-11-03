/**
 * N-075 — the multi-output continuation path (`call(..., { outputs: [...] })`)
 * built each output from the bare code script and dropped the 1sat inscription
 * envelope, while the single-output path (`getLockingScript()`) kept it. The
 * covenant's `_codePart` includes the envelope, so the hashOutputs check on
 * the multi-output spend could never match.
 *
 * Proves: with an inscription attached, every output of a multi-output call
 * is byte-identical to the locking script the single-output path produces for
 * the same state (code + envelope + OP_RETURN + state), and the envelope parses
 * back out of it.
 *
 * Does NOT prove: that a full spend validates under Spend.validate (the test
 * inspects the outputs the SDK commits to, not an executed covenant), nor the
 * same fix in the other SDKs (each carries its own test).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { buildP2PKHScript } from '../script-utils.js';
import { parseInscriptionEnvelope } from '../ordinals/envelope.js';

const SIGNER_KEY = '0000000000000000000000000000000000000000000000000000000000000003';

const SOURCE = `
import { StatefulSmartContract } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count = this.count + 1n;
  }
}
`;

describe('N-075 multi-output continuation keeps the inscription envelope', () => {
  it('each multi-output script equals the single-output locking script for that state', async () => {
    const r = compile(SOURCE, { fileName: 'Counter.runar.ts' });
    if (!r.artifact) throw new Error(`compile failed: ${JSON.stringify(r.diagnostics)}`);

    const signer = new LocalSigner(SIGNER_KEY);
    const address = await signer.getAddress();
    const pubKey = await signer.getPublicKey();
    const provider = new MockProvider();
    provider.addUtxo(address, {
      txid: 'aa'.repeat(32),
      outputIndex: 0,
      satoshis: 100_000,
      script: buildP2PKHScript(pubKey),
    });

    const inscription = { contentType: 'text/plain', data: Buffer.from('hello').toString('hex') };
    const contract = new RunarContract(r.artifact, [0n]).withInscription(inscription);
    contract.connect(provider, signer);
    await contract.deploy({ satoshis: 5000, changeAddress: address });

    const prepared = await contract.prepareCall(
      'increment', [],
      { outputs: [{ satoshis: 2000, state: { count: 7n } }, { satoshis: 2000, state: { count: 9n } }] },
    );
    expect(prepared._contractOutputs).toHaveLength(2);

    for (const [i, count] of [7n, 9n].entries()) {
      const reference = new RunarContract(r.artifact, [count]).withInscription(inscription);
      const expected = reference.getLockingScript();
      expect(prepared._contractOutputs[i]!.script).toBe(expected);
      expect(parseInscriptionEnvelope(prepared._contractOutputs[i]!.script)).not.toBeNull();
    }
  });
});
