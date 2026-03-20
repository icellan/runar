/**
 * addRawOutput tests — verify that contracts using addRawOutput compile
 * and execute correctly in the interpreter.
 *
 * addRawOutput(satoshis, scriptBytes) creates an output with caller-specified
 * script bytes instead of the contract's own codePart. This enables protocols
 * that need heterogeneous outputs (e.g., paying to a P2PKH address alongside
 * a contract continuation).
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { TestContract } from '../test-contract.js';
import { ALICE } from '../test-keys.js';
import { signTestMessage } from '../crypto/ecdsa.js';

const rawOutputSource = `
import { StatefulSmartContract, assert, checkSig, cat, toByteString } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class RawOutputContract extends StatefulSmartContract {
  owner: PubKey;
  counter: bigint;

  constructor(owner: PubKey, counter: bigint) {
    super(owner, counter);
    this.owner = owner;
    this.counter = counter;
  }

  public increment(sig: Sig, rawScript: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addOutput(1n, this.owner, this.counter + 1n);
    this.addRawOutput(1n, rawScript);
  }
}
`;

const rawOutputOnlySource = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class RawOnly extends StatefulSmartContract {
  owner: PubKey;
  value: bigint;

  constructor(owner: PubKey, value: bigint) {
    super(owner, value);
    this.owner = owner;
    this.value = value;
  }

  public cancel(sig: Sig, payoutScript: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addRawOutput(this.value, payoutScript);
  }
}
`;

const statelessRawOutputSource = `
import { SmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class StatelessRaw extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

  public unlock(sig: Sig, script: ByteString) {
    assert(checkSig(sig, this.owner));
    this.addRawOutput(1n, script);
  }
}
`;

describe('addRawOutput', () => {
  describe('Compilation', () => {
    it('compiles a contract with addOutput + addRawOutput', () => {
      const result = compile(rawOutputSource, { fileName: 'RawOutputContract.runar.ts' });
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors).toHaveLength(0);
      expect(result.success).toBe(true);
    });

    it('compiles a contract with only addRawOutput', () => {
      const result = compile(rawOutputOnlySource, { fileName: 'RawOnly.runar.ts' });
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors).toHaveLength(0);
      expect(result.success).toBe(true);
    });

    it('rejects addRawOutput in a stateless SmartContract', () => {
      const result = compile(statelessRawOutputSource, { fileName: 'StatelessRaw.runar.ts' });
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe('Interpreter execution (TestContract)', () => {
    const aliceSig = signTestMessage(ALICE.privKey);

    it('increment with raw output: interpreter succeeds and produces 2 outputs', () => {
      const contract = TestContract.fromSource(
        rawOutputSource,
        { owner: ALICE.pubKey, counter: 0n },
        'RawOutputContract.runar.ts',
      );
      const result = contract.call('increment', {
        sig: aliceSig,
        rawScript: '76a914' + '00'.repeat(20) + '88ac',
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(2);
      expect(result.outputs![1]).toHaveProperty('_rawScript');
    });

    it('cancel with only raw output: interpreter succeeds', () => {
      const contract = TestContract.fromSource(
        rawOutputOnlySource,
        { owner: ALICE.pubKey, value: 1000n },
        'RawOnly.runar.ts',
      );
      const result = contract.call('cancel', {
        sig: aliceSig,
        payoutScript: '76a914' + '00'.repeat(20) + '88ac',
      });
      expect(result.success).toBe(true);
      expect(result.outputs).toHaveLength(1);
      expect(result.outputs![0]).toHaveProperty('_rawScript');
    });
  });
});
