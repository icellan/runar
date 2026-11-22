/**
 * #213, SDK side — defence in depth only.
 *
 * The consensus defence is the covenant's entry gate on `_changePKH`
 * (`OP_SIZE 0x14 OP_NUMEQUALVERIFY`, proved under strict Spend in
 * runar-testing's pr-b-width-gates-spend.test.ts). `RunarContract` derives
 * its change PKH as hash160(pubkey), always 20 bytes; `assembleMultiContractCall`
 * takes `changePKH` from the caller, so it must refuse anything that is not
 * exactly 20 bytes of hex before building a transaction.
 *
 * Proves: a 19-, 21- and 54-byte (the #213 attack shape) or non-hex
 * changePKH is refused with a message naming the input. Does not prove:
 * anything on chain.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';
import { assembleMultiContractCall } from '../multi-contract.js';

// D25: the addOutput sibling keeps the contract on ALL (a mutate-only-only
// contract commits under SINGLE and takes no changePKH at all), so increment
// still declares `_changePKH`.
const SRC = `import { StatefulSmartContract } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count = this.count + 1n; }
  public bump() { this.addOutput(1n, this.count + 1n); }
}
`;

const r = compile(SRC, { fileName: 'Counter.runar.ts' });
if (!r.artifact) throw new Error(JSON.stringify(r.diagnostics));
const artifact = r.artifact;

function input(changePKH: string) {
  const contract = new RunarContract(artifact, [0n]);
  return {
    contract,
    method: 'increment',
    args: [],
    utxo: { txid: 'ab'.repeat(32), outputIndex: 0, satoshis: 10_000, script: contract.getLockingScript() },
    changePKH,
  };
}

describe('#213: assembleMultiContractCall refuses a changePKH that is not 20 bytes', () => {
  for (const bytes of [19, 21, 54]) {
    it(`refuses ${bytes} bytes`, async () => {
      await expect(
        assembleMultiContractCall([input('ab'.repeat(bytes))], [{ satoshis: 1, script: '51' }], { dryRun: false }),
      ).rejects.toThrow(/input 0: changePKH \(Ripemd160\) must be exactly 20 bytes/);
    });
  }
  it('refuses non-hex', async () => {
    await expect(
      assembleMultiContractCall([input('zz'.repeat(20))], [{ satoshis: 1, script: '51' }], { dryRun: false }),
    ).rejects.toThrow(/changePKH \(Ripemd160\) must be exactly 20 bytes of hex, got a non-hex string/);
  });
  it('accepts exactly 20 bytes', async () => {
    const out = await assembleMultiContractCall([input('ab'.repeat(20))], [{ satoshis: 1, script: '51' }], { dryRun: false });
    expect(out.unlocks[0]).toContain('14' + 'ab'.repeat(20));
  });
});
