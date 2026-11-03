/**
 * N-048 (external "PrematurePeek"): a computed FixedArray index was hoisted
 * ahead of an earlier side effect in the same statement.
 *
 * Pass 3b binds a computed index to `const __idx_K = <index>` in front of its
 * whole statement. In
 *
 *   assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);
 *
 * that put `__idx_0 = this.cursor % 2n` BEFORE the increment, so the gate
 * read the pre-increment slot. At cursor 0 the source reads `enabled[1] = 0`
 * and must reject; the compiled script read `enabled[0] = 1` and paid an
 * outsider 199,000 sat under `@bsv/sdk`'s real `Spend` (all seven tiers,
 * txid 78012821… in the triage probe).
 *
 * The fix refuses any hoist that would reorder evaluation (the AST has no
 * let-expression, so the index cannot be bound at the read's own position).
 *
 * What this proves:
 *  - the reported shape no longer compiles; if a compiler ever accepts it
 *    again, the resulting script is driven through the real `Spend` and must
 *    refuse the outsider spend, so a regression to the old lowering fails here;
 *  - the order-preserving spelling (increment in its own statement) still
 *    compiles, binds `__idx_*` after the `update_prop cursor` in ANF, and under
 *    the real `Spend` rejects the spend at cursor 0 and accepts it at cursor 1,
 *    exactly as the source says.
 * What it does not prove: the other six tiers (their own suites and
 * conformance/negatives/N120–N122 cover them), or any shape beyond the ones
 * named in 03b-expand-fixed-arrays.test.ts.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner } from 'runar-sdk';
import { PrivateKey } from '@bsv/sdk';

const FUNDER = PrivateKey.fromString('c3'.repeat(32), 16);
const ATTACKER = PrivateKey.fromString('d4'.repeat(32), 16);
const p2pkh = (k: PrivateKey): string => '76a914' + (k.toPublicKey().toHash('hex') as string) + '88ac';

const PEEK = `import { StatefulSmartContract, FixedArray, ByteString, assert } from 'runar-lang';
export class RotatingVault extends StatefulSmartContract {
  readonly enabled: FixedArray<bigint, 2> = [1n, 0n];
  cursor: bigint;
  constructor(cursor: bigint) { super(cursor); this.cursor = cursor; }
  public release(destination: ByteString) {
    assert((++this.cursor > 0n) && this.enabled[this.cursor % 2n] === 1n);
    this.addRawOutput(199000n, destination);
  }
}`;

const SPLIT = PEEK.replace(
  'assert((++this.cursor > 0n) && this.enabled[this.cursor % 2n] === 1n);',
  '++this.cursor;\n    assert(this.enabled[this.cursor % 2n] === 1n);',
);

/** Deploy at `cursor`, then an outsider calls `release` under the real Spend. */
async function outsiderRelease(artifact: unknown, cursor: bigint): Promise<void> {
  const provider = new MockProvider();
  provider.enableBroadcastValidation();
  const funder = new LocalSigner(FUNDER.toString());
  provider.addUtxo(await funder.getAddress(), {
    txid: 'ee'.repeat(32),
    outputIndex: 0,
    satoshis: 1_000_000,
    script: p2pkh(FUNDER),
  });
  const c = new RunarContract(artifact as never, [cursor]);
  c.connect(provider, funder);
  await c.deploy({ satoshis: 200_000 });
  c.connect(provider, new LocalSigner(ATTACKER.toString()));
  await c.call('release', [p2pkh(ATTACKER)]);
}

describe('N-048: FixedArray index keeps source evaluation order', () => {
  it('refuses the reported shape; any script it would compile must reject the outsider spend', async () => {
    const r = compile(PEEK, { fileName: 'RotatingVault.runar.ts' });
    if (r.success && r.artifact) {
      // Pre-fix path: the script read enabled[0] at cursor 0 and paid out.
      await expect(outsiderRelease(r.artifact, 0n)).rejects.toThrow();
    }
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toContain(
      'FixedArray index would be evaluated out of source order',
    );
  });

  it('the split spelling binds the index after the increment and follows the source', async () => {
    const r = compile(SPLIT, { fileName: 'RotatingVault.runar.ts', includeIR: true } as never);
    expect(r.success, r.diagnostics.map((d) => d.message).join('; ')).toBe(true);
    const anf = (r as unknown as { anf: { methods: Array<{ name: string; body: Array<{ name: string; value: { kind: string; name?: string } }> }> } }).anf;
    const body = anf.methods.find((m) => m.name === 'release')!.body;
    const idx = body.findIndex((b) => b.name.startsWith('__idx_'));
    const inc = body.findIndex((b) => b.value.kind === 'update_prop' && b.value.name === 'cursor');
    expect(idx).toBeGreaterThan(-1);
    expect(inc).toBeGreaterThan(-1);
    expect(idx).toBeGreaterThan(inc);

    // cursor 0 -> 1, enabled[1] = 0: the source forbids it.
    await expect(outsiderRelease(r.artifact, 0n)).rejects.toThrow();
    // cursor 1 -> 2, enabled[0] = 1: the source allows it.
    await expect(outsiderRelease(r.artifact, 1n)).resolves.toBeUndefined();
  }, 60_000);
});
