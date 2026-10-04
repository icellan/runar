/**
 * N-045 (EXT-2 WideHash), SDK side — defence in depth only.
 *
 * The on-chain state reader slices each fixed-width byte field (PubKey 33,
 * Addr / Ripemd160 20, Sha256 32, Point / P256Point 64, P384Point 96) at its
 * declared width, so a wrong-width value in a state section shifts every later
 * field. The consensus defence is the covenant's own
 * `OP_SIZE <width> OP_NUMEQUALVERIFY` before each continuation commit (proved
 * under strict Spend in runar-testing's n045-state-fixed-width-spend.test.ts).
 * This file pins the off-chain refusals: the state writer and the method args
 * reject a wrong-width fixed-width value before any transaction is built.
 * (Constructor args are deliberately NOT checked: `fromUtxo` builds its
 * contract with placeholder constructor args. A mutable field's deploy-time
 * value still goes through the state writer.)
 *
 * What it proves: `serializeState` refuses each of the seven types at width
 * +-1 and `call` refuses a 31/33/66-byte Sha256 argument, while the exact
 * width is accepted. What it does not prove: anything on chain.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import type { RunarArtifact, StateField } from 'runar-ir-schema';
import { serializeState } from '../state.js';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { MockSigner } from '../signers/mock.js';

const TYPES: [string, number][] = [
  ['PubKey', 33], ['Sha256', 32], ['Ripemd160', 20], ['Addr', 20],
  ['Point', 64], ['P256Point', 64], ['P384Point', 96],
];

const field = (name: string, type: string): StateField =>
  ({ name, type, index: 0 }) as unknown as StateField;

describe('N-045: the state writer refuses a wrong-width fixed-width value', () => {
  for (const [type, width] of TYPES) {
    for (const bad of [width - 1, width + 1]) {
      it(`${type}: refuses ${bad} bytes`, () => {
        expect(() => serializeState([field('k', type)], { k: 'ab'.repeat(bad) })).toThrow(
          new RegExp(`state field "k" \\(${type}\\) must be exactly ${width} bytes`),
        );
      });
    }
    it(`${type}: refuses non-hex of the right length`, () => {
      expect(() => serializeState([field('k', type)], { k: 'zz'.repeat(width) })).toThrow(/non-hex/);
    });
    it(`${type}: accepts exactly ${width} bytes`, () => {
      expect(serializeState([field('k', type)], { k: 'ab'.repeat(width) })).toBe('ab'.repeat(width));
    });
  }
});

const SRC = `import { StatefulSmartContract } from 'runar-lang';
import type { Sha256 } from 'runar-lang';

class Root extends StatefulSmartContract {
  root: Sha256;

  constructor(root: Sha256) {
    super(root);
    this.root = root;
  }

  public updateRoot(nextRoot: Sha256) {
    this.root = nextRoot;
  }
}
`;

function artifact(): RunarArtifact {
  const r = compile(SRC, { fileName: 'Root.runar.ts' });
  if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  return r.artifact as unknown as RunarArtifact;
}

describe('N-045: method args refuse a wrong-width Sha256', () => {
  const art = artifact();

  for (const bad of [31, 33, 66]) {
    it(`call refuses a ${bad}-byte Sha256 argument before building a transaction`, async () => {
      const provider = new MockProvider();
      const signer = new MockSigner();
      const c = new RunarContract(art, ['11'.repeat(32)]);
      provider.addUtxo(await signer.getAddress(), {
        txid: 'aa'.repeat(32), outputIndex: 0, satoshis: 1_000_000, script: '76a914' + '00'.repeat(20) + '88ac',
      });
      c.connect(provider, signer);
      // Pretend deployed: the refusal must fire before any UTXO is touched.
      (c as unknown as { currentUtxo: unknown }).currentUtxo = {
        txid: 'bb'.repeat(32), outputIndex: 0, satoshis: 10_000, script: c.getLockingScript(),
      };
      const before = provider.getBroadcastedTxs().length;
      await expect(c.call('updateRoot', ['22'.repeat(bad)])).rejects.toThrow(
        /arg 'nextRoot' \(index 0\).*\(Sha256\) must be exactly 32 bytes/,
      );
      expect(provider.getBroadcastedTxs().length).toBe(before);
    });
  }
});
