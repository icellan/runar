import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

// ---------------------------------------------------------------------------
// Array literal support — needed for checkMultiSig
// ---------------------------------------------------------------------------

describe('ArrayLiteralExpression', () => {
  it('parses array literals in checkMultiSig calls', () => {
    const source = `
      class MultiSigWallet extends SmartContract {
        readonly pk1: PubKey;
        readonly pk2: PubKey;
        readonly pk3: PubKey;

        constructor(pk1: PubKey, pk2: PubKey, pk3: PubKey) {
          super(pk1, pk2, pk3);
          this.pk1 = pk1;
          this.pk2 = pk2;
          this.pk3 = pk3;
        }

        public spend(sig1: Sig, sig2: Sig) {
          assert(checkMultiSig([sig1, sig2], [this.pk1, this.pk2, this.pk3]));
        }
      }
    `;
    const result = compile(source, { typecheckOnly: true });
    expect(result.diagnostics.filter(d => d.severity === 'error')).toEqual([]);
  });

  it('compiles checkMultiSig through full pipeline to Bitcoin Script', () => {
    const source = `
      class MultiSig2of3 extends SmartContract {
        readonly pk1: PubKey;
        readonly pk2: PubKey;
        readonly pk3: PubKey;

        constructor(pk1: PubKey, pk2: PubKey, pk3: PubKey) {
          super(pk1, pk2, pk3);
          this.pk1 = pk1;
          this.pk2 = pk2;
          this.pk3 = pk3;
        }

        public spend(sig1: Sig, sig2: Sig) {
          assert(checkMultiSig([sig1, sig2], [this.pk1, this.pk2, this.pk3]));
        }
      }
    `;
    const result = compile(source);
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBeDefined();
    expect(result.scriptHex!.length).toBeGreaterThan(0);
    // OP_CHECKMULTISIG = 0xae should appear in the script
    expect(result.scriptHex!).toContain('ae');
  });

  it('produces ANF with array_literal nodes', () => {
    const source = `
      class MS extends SmartContract {
        readonly pk1: PubKey;
        readonly pk2: PubKey;

        constructor(pk1: PubKey, pk2: PubKey) {
          super(pk1, pk2);
          this.pk1 = pk1;
          this.pk2 = pk2;
        }

        public spend(sig: Sig) {
          assert(checkMultiSig([sig], [this.pk1, this.pk2]));
        }
      }
    `;
    const result = compile(source);
    expect(result.success).toBe(true);
    expect(result.anf).toBeDefined();

    // Check that the ANF has array_literal nodes
    const spendMethod = result.anf!.methods.find(m => m.name === 'spend');
    expect(spendMethod).toBeDefined();
    const arrayLiterals = spendMethod!.body.filter(b => b.value.kind === 'array_literal');
    expect(arrayLiterals.length).toBe(2); // one for sigs, one for pks
  });

  it('type-checks array element type consistency', () => {
    const source = `
      class C extends SmartContract {
        readonly pk: PubKey;

        constructor(pk: PubKey) {
          super(pk);
          this.pk = pk;
        }

        public m(sig: Sig, val: bigint) {
          assert(checkMultiSig([sig, val], [this.pk]));
        }
      }
    `;
    const result = compile(source, { typecheckOnly: true });
    const errors = result.diagnostics.filter(d => d.severity === 'error');
    expect(errors.some(e => e.message.includes('type mismatch'))).toBe(true);
  });

  it('parses array literals in Solidity format', () => {
    const source = `
pragma runar ^0.1.0;

contract MultiSig is SmartContract {
    PubKey immutable pk1;
    PubKey immutable pk2;

    constructor(PubKey _pk1, PubKey _pk2) {
        pk1 = _pk1;
        pk2 = _pk2;
    }

    function spend(Sig sig1, Sig sig2) public {
        require(checkMultiSig([sig1, sig2], [pk1, pk2]));
    }
}
    `;
    const result = compile(source, { fileName: 'MultiSig.runar.sol' });
    expect(result.success).toBe(true);
    expect(result.scriptHex).toBeDefined();
  });
});
