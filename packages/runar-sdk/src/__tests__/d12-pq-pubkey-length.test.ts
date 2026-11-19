/**
 * D12 PQ-F1: a post-quantum public key of the wrong length must be refused at
 * compile time (constructorArgs) and at RunarContract construction, from the
 * verifier's parameter set. The parameter is a plain ByteString, so nothing
 * width-checked it; the output it locked refused every honest signature.
 *
 * The lengths come from the codegen split points: verifyWOTS pubSeed(32) ||
 * pkRoot(32); SLH-DSA PK.seed(n) || PK.root(n), n = 16/24/32.
 *
 * Proves: wrong lengths are refused, the right length compiles and
 * constructs, and a key committed only by hash160 is not (and cannot be)
 * checked. The deploy-time check reads the verifier wiring from the
 * artifact's ANF, which `compile()` emits for stateful contracts only; a
 * stateless artifact is covered by the compile-time constructorArgs check. Does not prove: other tiers (their own tests).
 */
import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';

const wots = `import { SmartContract, assert, verifyWOTS } from 'runar-lang';
import type { ByteString } from 'runar-lang';
class W extends SmartContract {
  readonly pubkey: ByteString;
  constructor(pubkey: ByteString) { super(pubkey); this.pubkey = pubkey; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pubkey)); }
}
`;
const slh = (set: string) => `import { SmartContract, assert, verifySLHDSA_SHA2_${set} } from 'runar-lang';
import type { ByteString } from 'runar-lang';
class S extends SmartContract {
  readonly pk: ByteString;
  constructor(pk: ByteString) { super(pk); this.pk = pk; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifySLHDSA_SHA2_${set}(msg, sig, this.pk)); }
}
`;
const hashed = `import { StatefulSmartContract, assert, verifyWOTS, hash160 } from 'runar-lang';
import type { ByteString, Addr } from 'runar-lang';
class H extends StatefulSmartContract {
  readonly pkh: Addr;
  n: bigint;
  constructor(pkh: Addr, n: bigint) { super(pkh, n); this.pkh = pkh; this.n = n; }
  public spend(msg: ByteString, sig: ByteString, pk: ByteString) {
    assert(hash160(pk) === this.pkh);
    assert(verifyWOTS(msg, sig, pk));
    this.n = this.n + 1n;
  }
}
`;

const CASES: Array<[string, string, string, number]> = [
  ['verifyWOTS', wots, 'pubkey', 64],
  ['SLH-DSA 128s', slh('128s'), 'pk', 32],
  ['SLH-DSA 128f', slh('128f'), 'pk', 32],
  ['SLH-DSA 192s', slh('192s'), 'pk', 48],
  ['SLH-DSA 192f', slh('192f'), 'pk', 48],
  ['SLH-DSA 256s', slh('256s'), 'pk', 64],
  ['SLH-DSA 256f', slh('256f'), 'pk', 64],
];

/** A stateful twin: its artifact always carries the ANF the deploy check reads. */
function statefulTwin(src: string): string {
  return src
    .replace('SmartContract,', 'StatefulSmartContract,')
    .replace(/extends SmartContract \{\n  readonly (\w+): ByteString;\n  constructor\((\w+): ByteString\) \{ super\(\w+\); this\.\w+ = \w+; \}/,
      (_m, prop) => `extends StatefulSmartContract {\n  readonly ${prop}: ByteString;\n  n: bigint;\n` +
        `  constructor(${prop}: ByteString, n: bigint) { super(${prop}, n); this.${prop} = ${prop}; this.n = n; }`)
    .replace(/\)\); \}\n\}/, ')); this.n = this.n + 1n; }\n}');
}

function artifactOf(src: string) {
  const r = compile(src, { fileName: 'C.runar.ts' });
  if (!r.artifact) throw new Error(JSON.stringify(r.diagnostics));
  return r.artifact;
}

describe('D12 PQ-F1: wrong-length PQ public keys are refused', () => {
  for (const [label, src, prop, n] of CASES) {
    describe(label, () => {
      const art = artifactOf(statefulTwin(src));
      for (const len of [0, n / 2, n - 1, n + 1, 2 * n]) {
        it(`RunarContract (stateful artifact) refuses a ${len}-byte key`, () => {
          expect(() => new RunarContract(art, ['ab'.repeat(len), 0n])).toThrow(new RegExp(`${n} bytes`));
        });
        it(`compile(constructorArgs) refuses a ${len}-byte key`, () => {
          const r = compile(src, { fileName: 'C.runar.ts', constructorArgs: { [prop]: 'ab'.repeat(len) } });
          expect(r.success).toBe(false);
          expect(r.diagnostics.map((d) => d.message).join('\n')).toMatch(new RegExp(`${n} bytes`));
        });
      }
      it(`accepts a ${n}-byte key`, () => {
        expect(() => new RunarContract(art, ['ab'.repeat(n), 0n])).not.toThrow();
        // One full baked compile is enough to show the gate passes a right key
        // (the SLH-DSA scripts are hundreds of KB each).
        if (label === 'verifyWOTS') {
          const r = compile(src, { fileName: 'C.runar.ts', constructorArgs: { [prop]: 'ab'.repeat(n) } });
          expect(r.success).toBe(true);
        }
      });
    });
  }

  it('a hash-committed key is not checked (it cannot be)', () => {
    const art = artifactOf(hashed);
    expect(art.anf).toBeDefined();
    expect(() => new RunarContract(art, ['ab'.repeat(20), 0n])).not.toThrow();
  });
});
