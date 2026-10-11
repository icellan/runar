/**
 * F-222: a Sig consumed once in each arm of an if/else used to be refused by
 * the affine checker as a double consumption. The checker now accepts it, so
 * this test checks that the newly admitted program also spends correctly.
 * The checker change never reaches codegen, but no tier had compiled this
 * shape before.
 *
 * Proves: the TS-compiled locking script for "checkSig(sig, pkA) in the then
 * arm, checkSig(sig, pkB) in the else arm" accepts a real signature by A when
 * `useA` is true and by B when it is false, and refuses the other key in each
 * arm; and the same for a nested if/else with one consumption in each of its
 * three arms (the nested shape lowers with a DUP/SWAP/NIP stack dance that
 * the flat one does not). It runs through @bsv/sdk's Spend
 * (ScriptExecutionContract), not the ANF interpreter.
 * Does not prove: the other six tiers' bytes (the 7-tier hex parity test in
 * conformance/negatives/f222-affine-if-else-parity.test.ts pins those to the
 * same script), or behaviour under any sighash type other than ALL|FORKID.
 */

import { describe, it, expect } from 'vitest';
import { PrivateKey } from '@bsv/sdk';
import { ScriptExecutionContract } from '../script-execution.js';
import { ALICE, BOB, CHARLIE } from '../test-keys.js';

const SOURCE = `
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class EitherKey extends SmartContract {
  readonly pkA: PubKey;
  readonly pkB: PubKey;

  constructor(pkA: PubKey, pkB: PubKey) {
    super(pkA, pkB);
    this.pkA = pkA;
    this.pkB = pkB;
  }

  public unlock(sig: Sig, useA: boolean) {
    if (useA) {
      assert(checkSig(sig, this.pkA));
    } else {
      assert(checkSig(sig, this.pkB));
    }
  }
}
`;

const NESTED_SOURCE = `
import { SmartContract, assert, checkSig, PubKey, Sig } from 'runar-lang';

class OneOfThree extends SmartContract {
  readonly pkA: PubKey;
  readonly pkB: PubKey;
  readonly pkC: PubKey;

  constructor(pkA: PubKey, pkB: PubKey, pkC: PubKey) {
    super(pkA, pkB, pkC);
    this.pkA = pkA;
    this.pkB = pkB;
    this.pkC = pkC;
  }

  public unlock(sig: Sig, useA: boolean, useB: boolean) {
    if (useA) {
      assert(checkSig(sig, this.pkA));
    } else {
      if (useB) {
        assert(checkSig(sig, this.pkB));
      } else {
        assert(checkSig(sig, this.pkC));
      }
    }
  }
}
`;

function contract(): ScriptExecutionContract {
  return ScriptExecutionContract.fromSource(
    SOURCE, { pkA: ALICE.pubKey, pkB: BOB.pubKey }, 'EitherKey.runar.ts',
  );
}

const alice = new PrivateKey(ALICE.privKey, 16);
const bob = new PrivateKey(BOB.privKey, 16);
const charlie = new PrivateKey(CHARLIE.privKey, 16);

describe('F-222: Sig consumed once per if/else arm executes correctly', () => {
  it('then arm spends with a real signature by pkA', () => {
    expect(contract().executeSigned('unlock', ['placeholder', true], 0, alice).success).toBe(true);
  });

  it('else arm spends with a real signature by pkB', () => {
    expect(contract().executeSigned('unlock', ['placeholder', false], 0, bob).success).toBe(true);
  });

  it('then arm refuses a signature by pkB', () => {
    expect(contract().executeSigned('unlock', ['placeholder', true], 0, bob).success).toBe(false);
  });

  it('else arm refuses a signature by pkA', () => {
    expect(contract().executeSigned('unlock', ['placeholder', false], 0, alice).success).toBe(false);
  });
});

describe('F-222: Sig consumed once per arm of a nested if/else executes correctly', () => {
  const nested = (): ScriptExecutionContract => ScriptExecutionContract.fromSource(
    NESTED_SOURCE, { pkA: ALICE.pubKey, pkB: BOB.pubKey, pkC: CHARLIE.pubKey }, 'OneOfThree.runar.ts',
  );
  const run = (useA: boolean, useB: boolean, key: PrivateKey): boolean =>
    nested().executeSigned('unlock', ['placeholder', useA, useB], 0, key).success;

  it('each arm spends with its own key', () => {
    expect(run(true, false, alice)).toBe(true);
    expect(run(false, true, bob)).toBe(true);
    expect(run(false, false, charlie)).toBe(true);
  });

  it('each arm refuses the other two keys', () => {
    expect(run(true, false, bob)).toBe(false);
    expect(run(true, false, charlie)).toBe(false);
    expect(run(false, true, alice)).toBe(false);
    expect(run(false, true, charlie)).toBe(false);
    expect(run(false, false, alice)).toBe(false);
    expect(run(false, false, bob)).toBe(false);
  });
});
