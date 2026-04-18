/**
 * addDataOutput tests — verify that contracts using addDataOutput compile
 * and execute correctly in the interpreter.
 *
 * addDataOutput(satoshis, scriptBytes) registers an additional transaction
 * output that is NOT a state continuation. The continuation-hash composition
 * becomes:
 *   hash256([state outputs] || [data outputs] || changeOutput)
 * Data outputs are inserted in source order between state outputs and the
 * change output.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { TestContract } from '../test-contract.js';
import { ALICE } from '../test-keys.js';
import { signTestMessage } from '../crypto/ecdsa.js';

const multiOutputWithDataSource = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class FT extends StatefulSmartContract {
  owner: PubKey;
  balance: bigint;

  constructor(owner: PubKey, balance: bigint) {
    super(owner, balance);
    this.owner = owner;
    this.balance = balance;
  }

  public transfer(sig: Sig, to: PubKey, amount: bigint, sats: bigint, note: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addOutput(sats, to, amount);
    this.addOutput(sats, this.owner, this.balance - amount);
    this.addDataOutput(0n, note);
  }
}
`;

const singleStateWithDataSource = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class Counter extends StatefulSmartContract {
  readonly owner: PubKey;
  count: bigint;

  constructor(owner: PubKey, count: bigint) {
    super(owner, count);
    this.owner = owner;
    this.count = count;
  }

  public bump(sig: Sig, payload: ByteString) {
    assert(checkSig(sig, this.owner));
    this.count = this.count + 1n;
    this.addDataOutput(0n, payload);
  }
}
`;

const nonMutatingWithDataSource = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class PingContract extends StatefulSmartContract {
  readonly owner: PubKey;
  counter: bigint;

  constructor(owner: PubKey, counter: bigint) {
    super(owner, counter);
    this.owner = owner;
    this.counter = counter;
  }

  public ping(sig: Sig, payload: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addDataOutput(0n, payload);
  }
}
`;

const statelessDataOutputSource = `
import { SmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class StatelessData extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public unlock(sig: Sig, payload: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addDataOutput(0n, payload);
  }
}
`;

describe('addDataOutput', () => {
  describe('Compilation', () => {
    it('compiles a contract with addOutput + addDataOutput (multi-state + data)', () => {
      const result = compile(multiOutputWithDataSource, { fileName: 'FT.runar.ts' });
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors).toHaveLength(0);
      expect(result.success).toBe(true);
    });

    it('compiles a single-state contract with addDataOutput', () => {
      const result = compile(singleStateWithDataSource, { fileName: 'Counter.runar.ts' });
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors).toHaveLength(0);
      expect(result.success).toBe(true);
    });

    it('compiles a non-mutating method that emits addDataOutput', () => {
      const result = compile(nonMutatingWithDataSource, { fileName: 'PingContract.runar.ts' });
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors).toHaveLength(0);
      expect(result.success).toBe(true);
    });

    it('rejects addDataOutput in a stateless SmartContract', () => {
      const result = compile(statelessDataOutputSource, { fileName: 'StatelessData.runar.ts' });
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe('Interpreter execution (TestContract)', () => {
    const aliceSig = signTestMessage(ALICE.privKey);

    it('bump with data output: produces 2 outputs (state + data)', () => {
      const contract = TestContract.fromSource(
        singleStateWithDataSource,
        { owner: ALICE.pubKey, count: 0n },
        'Counter.runar.ts',
      );
      const result = contract.call('bump', {
        sig: aliceSig,
        payload: '6a0568656c6c6f', // OP_RETURN "hello"
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      // The data output is recorded under _dataScript, distinguishing it
      // from _rawScript (addRawOutput) and state outputs.
      expect(result.outputs![0]).toHaveProperty('_dataScript');
    });

    it('transfer with data output: state outputs + data output recorded in order', () => {
      const contract = TestContract.fromSource(
        multiOutputWithDataSource,
        { owner: ALICE.pubKey, balance: 1000n },
        'FT.runar.ts',
      );
      const result = contract.call('transfer', {
        sig: aliceSig,
        to: ALICE.pubKey,
        amount: 100n,
        sats: 1n,
        note: '6a0568656c6c6f',
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(3);
      // First two outputs are the state outputs; third is the data output.
      expect(result.outputs![2]).toHaveProperty('_dataScript');
      expect(result.outputs![0]).not.toHaveProperty('_dataScript');
      expect(result.outputs![1]).not.toHaveProperty('_dataScript');
    });

    it('non-mutating method with only data output: interpreter succeeds', () => {
      const contract = TestContract.fromSource(
        nonMutatingWithDataSource,
        { owner: ALICE.pubKey, counter: 42n },
        'PingContract.runar.ts',
      );
      const result = contract.call('ping', {
        sig: aliceSig,
        payload: '6a0470696e67',
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs![0]).toHaveProperty('_dataScript');
    });
  });
});
