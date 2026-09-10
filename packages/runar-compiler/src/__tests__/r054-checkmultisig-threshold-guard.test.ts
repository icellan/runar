import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
// @ts-expect-error vitest resolves this via alias
import { ScriptVM, testKey } from 'runar-testing';

// ---------------------------------------------------------------------------
// R-054 — checkMultiSig must reject a degenerate threshold at COMPILE time.
//
// Two adversarial shapes, both silently accepted before this guard:
//
//   1. `checkMultiSig([], [pk])` lowers to
//        OP_0 OP_0 <pk> OP_1 OP_CHECKMULTISIG
//      i.e. nSigs = 0. OP_CHECKMULTISIG with zero required signatures pops the
//      pubkeys, verifies nothing, and pushes TRUE. The deployed output is
//      ANYONE-CAN-SPEND while the source reads like an authorization check.
//
//   2. `checkMultiSig([s1, s2], [pk])` — m > n — can never be satisfied by any
//      witness. That output is permanently UNSPENDABLE. Funds loss of the
//      opposite sign.
//
// The guard belongs in the compiler, not in emitted opcodes: adding runtime
// defence would move bytes for every existing valid contract.
// ---------------------------------------------------------------------------

/** Source of an m-of-n gate with `nSigs` witness sigs and `nPks` pubkeys. */
function multiSigSource(nSigs: number, nPks: number): string {
  const props = Array.from({ length: nPks }, (_, i) => `readonly pk${i + 1}: PubKey;`).join('\n    ');
  const ctorParams = Array.from({ length: nPks }, (_, i) => `pk${i + 1}: PubKey`).join(', ');
  const ctorArgs = Array.from({ length: nPks }, (_, i) => `pk${i + 1}`).join(', ');
  const ctorAssigns = Array.from({ length: nPks }, (_, i) => `this.pk${i + 1} = pk${i + 1};`).join('\n      ');
  const sigParams = Array.from({ length: nSigs }, (_, i) => `sig${i + 1}: Sig`).join(', ');
  const sigList = Array.from({ length: nSigs }, (_, i) => `sig${i + 1}`).join(', ');
  const pkList = Array.from({ length: nPks }, (_, i) => `this.pk${i + 1}`).join(', ');
  return `
  class MultiSigGate extends SmartContract {
    ${props}

    constructor(${ctorParams}) {
      super(${ctorArgs});
      ${ctorAssigns}
    }

    public spend(${sigParams}) {
      assert(checkMultiSig([${sigList}], [${pkList}]));
    }
  }
`;
}

function errorsOf(source: string): string[] {
  const result = compile(source);
  return result.diagnostics.filter(d => d.severity === 'error').map(d => d.message);
}

describe('R-054: checkMultiSig degenerate-threshold guard', () => {
  // -------------------------------------------------------------------------
  // The attack, executed.
  // -------------------------------------------------------------------------
  it('the nSigs=0 byte pattern really is anyone-can-spend under real @bsv/sdk script evaluation', () => {
    // These are the exact bytes the compiler emitted for
    // `assert(checkMultiSig([], [this.pk1]))` before the guard existed, with
    // the constructor slot substituted by a REAL compressed secp256k1 pubkey:
    //   PUSH33 <pk>  OP_0(dummy)  OP_0(nSigs)  OP_ROT  OP_1(nPks)  OP_CHECKMULTISIG
    const pk = testKey('alice').pubKey as string;
    expect(pk.length).toBe(66);
    const locking = '21' + pk + '00007b51ae';

    const vm = new ScriptVM();
    // The attacker supplies NOTHING: an empty unlocking script.
    const res = vm.execute(new Uint8Array(0), Buffer.from(locking, 'hex'));

    // Real secp256k1, no mock crypto: it still succeeds, because zero
    // signatures were required. This is the funds-loss shape being guarded.
    expect(res.error).toBeUndefined();
    expect(res.success).toBe(true);
  });

  it('no longer compiles that pattern: an empty signature array is rejected', () => {
    const errors = errorsOf(multiSigSource(0, 1));
    expect(errors.join('\n')).toMatch(/checkMultiSig/);
    expect(errors.join('\n')).toMatch(/at least one signature/i);
  });

  it('rejects m > n (2 signatures against 1 pubkey) — permanently unspendable', () => {
    const errors = errorsOf(multiSigSource(2, 1));
    expect(errors.join('\n')).toMatch(/checkMultiSig/);
    expect(errors.join('\n')).toMatch(/cannot exceed/i);
  });

  it('rejects an empty pubkey array', () => {
    const errors = errorsOf(multiSigSource(1, 0));
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.join('\n')).toMatch(/checkMultiSig/);
  });

  // -------------------------------------------------------------------------
  // Controls — these prove the guard rejected the attack, not checkMultiSig.
  // -------------------------------------------------------------------------
  it('control: a valid 1-of-1 still compiles', () => {
    const result = compile(multiSigSource(1, 1));
    expect(result.diagnostics.filter(d => d.severity === 'error')).toEqual([]);
    expect(result.success).toBe(true);
    expect(result.scriptHex).toMatch(/ae$/);
  });

  it('control: a valid 2-of-3 still compiles', () => {
    const result = compile(multiSigSource(2, 3));
    expect(result.diagnostics.filter(d => d.severity === 'error')).toEqual([]);
    expect(result.success).toBe(true);
  });

  it('control: m == n (3-of-3) still compiles', () => {
    const result = compile(multiSigSource(3, 3));
    expect(result.diagnostics.filter(d => d.severity === 'error')).toEqual([]);
    expect(result.success).toBe(true);
  });
});
