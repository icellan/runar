import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import type { ContractNode } from '../ir/index.js';
import type { ANFProgram, StackProgram } from '../ir/index.js';
import {
  assembleArtifact,
  serializeArtifact,
  deserializeArtifact,
} from '../artifact/assembler.js';
import type { RunarArtifact } from '../artifact/assembler.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseContract(source: string): ContractNode {
  const result = parse(source);
  if (!result.contract) {
    throw new Error(`Parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

function compileContract(source: string): {
  contract: ContractNode;
  anf: ANFProgram;
  stack: StackProgram;
} {
  const contract = parseContract(source);
  const anf = lowerToANF(contract);
  const stack = lowerToStack(anf);
  return { contract, anf, stack };
}

function assemble(source: string, options?: Parameters<typeof assembleArtifact>[5]): RunarArtifact {
  const { contract, anf, stack } = compileContract(source);
  return assembleArtifact(contract, anf, stack, 'deadbeef', 'OP_DUP OP_HASH160', options);
}

// ---------------------------------------------------------------------------
// Contract sources
// ---------------------------------------------------------------------------

const P2PKH_SOURCE = `
import { SmartContract, assert, checkSig, Sig, PubKey } from 'runar-lang';
export class P2PKH extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); }
  public unlock(sig: Sig): void { assert(checkSig(sig, this.pk)); }
  private helper(): void { assert(true); }
}`;

const COUNTER_SOURCE = `
import { StatefulSmartContract } from 'runar-lang';
export class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); }
  public increment(): void { this.count = this.count + 1n; }
  public getValue(): void { assert(this.count > 0n); }
}`;

const ADD_OUTPUT_SOURCE = `
import { StatefulSmartContract, PubKey, Sig, checkSig, assert } from 'runar-lang';
export class Splitter extends StatefulSmartContract {
  balance: bigint;
  constructor(balance: bigint) { super(balance); }
  public split(): void {
    this.addOutput(this.balance, this.balance);
    this.addOutput(this.balance, this.balance);
  }
}`;

const INITIALIZED_SOURCE = `
import { StatefulSmartContract } from 'runar-lang';
export class WithInit extends StatefulSmartContract {
  count: bigint = 0n;
  constructor() { super(0n); }
  public increment(): void { this.count = this.count + 1n; }
}`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Assembler', () => {
  // -------------------------------------------------------------------------
  // 1. Stateless contract ABI
  // -------------------------------------------------------------------------
  describe('stateless contract ABI', () => {
    it('has correct constructor params', () => {
      const artifact = assemble(P2PKH_SOURCE);
      expect(artifact.abi.constructor.params).toEqual([
        { name: 'pk', type: 'PubKey' },
      ]);
    });

    it('includes public methods in ABI', () => {
      const artifact = assemble(P2PKH_SOURCE);
      const publicMethods = artifact.abi.methods.filter(m => m.isPublic);
      expect(publicMethods).toHaveLength(1);
      expect(publicMethods[0]!.name).toBe('unlock');
      expect(publicMethods[0]!.params).toEqual([
        { name: 'sig', type: 'Sig' },
      ]);
    });

    it('includes private methods in ABI marked as non-public', () => {
      const artifact = assemble(P2PKH_SOURCE);
      const privateMethods = artifact.abi.methods.filter(m => !m.isPublic);
      expect(privateMethods).toHaveLength(1);
      expect(privateMethods[0]!.name).toBe('helper');
      expect(privateMethods[0]!.isPublic).toBe(false);
    });

    it('has no state fields', () => {
      const artifact = assemble(P2PKH_SOURCE);
      expect(artifact.stateFields).toBeUndefined();
    });

    it('has correct contract name and version fields', () => {
      const artifact = assemble(P2PKH_SOURCE);
      expect(artifact.contractName).toBe('P2PKH');
      expect(artifact.version).toBe('runar-v0.4.4');
      expect(artifact.script).toBe('deadbeef');
      expect(artifact.asm).toBe('OP_DUP OP_HASH160');
    });
  });

  // -------------------------------------------------------------------------
  // 2. Stateful contract ABI
  // -------------------------------------------------------------------------
  describe('stateful contract ABI', () => {
    it('injects change params on state-mutating method', () => {
      const artifact = assemble(COUNTER_SOURCE);
      const inc = artifact.abi.methods.find(m => m.name === 'increment')!;
      const paramNames = inc.params.map(p => p.name);
      expect(paramNames).toContain('_changePKH');
      expect(paramNames).toContain('_changeAmount');
      expect(paramNames).toContain('_newAmount');
      expect(paramNames).toContain('txPreimage');
    });

    it('has correct types on injected params', () => {
      const artifact = assemble(COUNTER_SOURCE);
      const inc = artifact.abi.methods.find(m => m.name === 'increment')!;
      const paramMap = Object.fromEntries(inc.params.map(p => [p.name, p.type]));
      expect(paramMap['_changePKH']).toBe('Ripemd160');
      expect(paramMap['_changeAmount']).toBe('bigint');
      expect(paramMap['_newAmount']).toBe('bigint');
      expect(paramMap['txPreimage']).toBe('SigHashPreimage');
    });

    it('has state fields for mutable properties', () => {
      const artifact = assemble(COUNTER_SOURCE);
      expect(artifact.stateFields).toBeDefined();
      expect(artifact.stateFields).toHaveLength(1);
      expect(artifact.stateFields![0]!.name).toBe('count');
      expect(artifact.stateFields![0]!.type).toBe('bigint');
    });

    it('does not mark state-mutating method as terminal', () => {
      const artifact = assemble(COUNTER_SOURCE);
      const inc = artifact.abi.methods.find(m => m.name === 'increment')!;
      expect(inc.isTerminal).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // 3. Terminal method detection
  // -------------------------------------------------------------------------
  describe('terminal method detection', () => {
    it('marks non-mutating method as terminal', () => {
      const artifact = assemble(COUNTER_SOURCE);
      const getValue = artifact.abi.methods.find(m => m.name === 'getValue')!;
      expect(getValue.isTerminal).toBe(true);
    });

    it('terminal method has txPreimage but no change params', () => {
      const artifact = assemble(COUNTER_SOURCE);
      const getValue = artifact.abi.methods.find(m => m.name === 'getValue')!;
      const paramNames = getValue.params.map(p => p.name);
      expect(paramNames).toContain('txPreimage');
      expect(paramNames).not.toContain('_changePKH');
      expect(paramNames).not.toContain('_changeAmount');
      expect(paramNames).not.toContain('_newAmount');
    });

    it('mutating method is not terminal', () => {
      const artifact = assemble(COUNTER_SOURCE);
      const inc = artifact.abi.methods.find(m => m.name === 'increment')!;
      expect(inc.isTerminal).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // 4. addOutput method
  // -------------------------------------------------------------------------
  describe('addOutput method', () => {
    it('gets _changePKH and _changeAmount but not _newAmount', () => {
      const artifact = assemble(ADD_OUTPUT_SOURCE);
      const split = artifact.abi.methods.find(m => m.name === 'split')!;
      const paramNames = split.params.map(p => p.name);
      expect(paramNames).toContain('_changePKH');
      expect(paramNames).toContain('_changeAmount');
      expect(paramNames).not.toContain('_newAmount');
      expect(paramNames).toContain('txPreimage');
    });

    it('is not marked as terminal', () => {
      const artifact = assemble(ADD_OUTPUT_SOURCE);
      const split = artifact.abi.methods.find(m => m.name === 'split')!;
      expect(split.isTerminal).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // 5. serializeArtifact/deserializeArtifact round-trip
  // -------------------------------------------------------------------------
  describe('serialize/deserialize round-trip', () => {
    it('preserves all fields through round-trip', () => {
      const artifact = assemble(COUNTER_SOURCE, {
        constructorSlots: [{ paramIndex: 0, byteOffset: 10 }],
        codeSeparatorIndex: 42,
      });
      const json = serializeArtifact(artifact);
      const restored = deserializeArtifact(json);

      expect(restored.version).toBe(artifact.version);
      expect(restored.compilerVersion).toBe(artifact.compilerVersion);
      expect(restored.contractName).toBe(artifact.contractName);
      expect(restored.script).toBe(artifact.script);
      expect(restored.asm).toBe(artifact.asm);
      expect(restored.abi).toEqual(artifact.abi);
      expect(restored.stateFields).toEqual(artifact.stateFields);
      expect(restored.constructorSlots).toEqual(artifact.constructorSlots);
      expect(restored.codeSeparatorIndex).toBe(artifact.codeSeparatorIndex);
    });

    it('preserves BigInt values in stateFields.initialValue', () => {
      const artifact = assemble(INITIALIZED_SOURCE);
      // The initialValue should be set from the ANF program
      expect(artifact.stateFields).toBeDefined();
      const countField = artifact.stateFields!.find(f => f.name === 'count');
      expect(countField).toBeDefined();
      expect(countField!.initialValue).toBe(0n);

      const json = serializeArtifact(artifact);
      const restored = deserializeArtifact(json);
      const restoredField = restored.stateFields!.find(f => f.name === 'count');
      expect(restoredField!.initialValue).toBe(0n);
    });
  });

  // -------------------------------------------------------------------------
  // 6. BigInt serialization format
  // -------------------------------------------------------------------------
  describe('BigInt serialization format', () => {
    it('serializes BigInt 42n to string "42n"', () => {
      const artifact = assemble(INITIALIZED_SOURCE);
      // Manually set a BigInt value to test the format
      artifact.stateFields![0]!.initialValue = 42n;
      const json = serializeArtifact(artifact);
      expect(json).toContain('"42n"');
    });

    it('serializes negative BigInt to "-1n"', () => {
      const artifact = assemble(INITIALIZED_SOURCE);
      artifact.stateFields![0]!.initialValue = -1n;
      const json = serializeArtifact(artifact);
      expect(json).toContain('"-1n"');
    });

    it('deserializes "42n" back to BigInt', () => {
      const json = '{"value": "42n"}';
      const parsed = JSON.parse(json, (_key, value) => {
        if (typeof value === 'string' && /^-?\d+n$/.test(value)) {
          return BigInt(value.slice(0, -1));
        }
        return value;
      });
      expect(parsed.value).toBe(42n);
    });
  });

  // -------------------------------------------------------------------------
  // 7. Constructor slots and codeSeparator
  // -------------------------------------------------------------------------
  describe('constructor slots and codeSeparator', () => {
    it('includes constructorSlots when provided', () => {
      const slots = [
        { paramIndex: 0, byteOffset: 5 },
        { paramIndex: 1, byteOffset: 40 },
      ];
      const artifact = assemble(P2PKH_SOURCE, { constructorSlots: slots });
      expect(artifact.constructorSlots).toEqual(slots);
    });

    it('omits constructorSlots when empty', () => {
      const artifact = assemble(P2PKH_SOURCE, { constructorSlots: [] });
      expect(artifact.constructorSlots).toBeUndefined();
    });

    it('includes codeSeparatorIndex when provided', () => {
      const artifact = assemble(COUNTER_SOURCE, { codeSeparatorIndex: 99 });
      expect(artifact.codeSeparatorIndex).toBe(99);
    });

    it('includes codeSeparatorIndices when provided', () => {
      const indices = [10, 50, 100];
      const artifact = assemble(COUNTER_SOURCE, { codeSeparatorIndices: indices });
      expect(artifact.codeSeparatorIndices).toEqual(indices);
    });

    it('omits codeSeparatorIndices when empty', () => {
      const artifact = assemble(COUNTER_SOURCE, { codeSeparatorIndices: [] });
      expect(artifact.codeSeparatorIndices).toBeUndefined();
    });

    it('omits codeSeparatorIndex when not provided', () => {
      const artifact = assemble(COUNTER_SOURCE);
      expect(artifact.codeSeparatorIndex).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // 8. includeIR option
  // -------------------------------------------------------------------------
  describe('includeIR option', () => {
    it('includes IR when option is true', () => {
      const artifact = assemble(P2PKH_SOURCE, { includeIR: true });
      expect(artifact.ir).toBeDefined();
      expect(artifact.ir!.anf).toBeDefined();
      expect(artifact.ir!.stack).toBeDefined();
      expect(artifact.ir!.anf!.contractName).toBe('P2PKH');
    });

    it('omits IR by default', () => {
      const artifact = assemble(P2PKH_SOURCE);
      expect(artifact.ir).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // 9. Property initializers
  // -------------------------------------------------------------------------
  describe('property initializers', () => {
    it('populates initialValue from ANF program', () => {
      const artifact = assemble(INITIALIZED_SOURCE);
      expect(artifact.stateFields).toBeDefined();
      expect(artifact.stateFields).toHaveLength(1);
      const countField = artifact.stateFields![0]!;
      expect(countField.name).toBe('count');
      expect(countField.initialValue).toBe(0n);
    });

    it('does not set initialValue when property has no initializer', () => {
      const artifact = assemble(COUNTER_SOURCE);
      expect(artifact.stateFields).toBeDefined();
      const countField = artifact.stateFields![0]!;
      expect(countField.name).toBe('count');
      expect(countField.initialValue).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Misc
  // -------------------------------------------------------------------------
  describe('compiler version', () => {
    it('uses default compiler version', () => {
      const artifact = assemble(P2PKH_SOURCE);
      expect(artifact.compilerVersion).toBe('0.4.4');
    });

    it('allows overriding compiler version', () => {
      const artifact = assemble(P2PKH_SOURCE, { compilerVersion: '1.2.3' });
      expect(artifact.compilerVersion).toBe('1.2.3');
    });
  });

  describe('buildTimestamp', () => {
    it('produces a valid ISO-8601 timestamp', () => {
      const artifact = assemble(P2PKH_SOURCE);
      const date = new Date(artifact.buildTimestamp);
      expect(date.getTime()).not.toBeNaN();
    });
  });

  // -------------------------------------------------------------------------
  // Synthetic-array marker guard
  // -------------------------------------------------------------------------
  //
  // A contract with hand-written properties named `user__0`, `user__1`,
  // `user__2` of the same type must NOT be re-grouped into a single
  // `FixedArray<bigint, 3>` state field / ABI entry. The pattern matches
  // the shape the expand-fixed-arrays pass produces, but without the
  // `__syntheticArrayChain` marker the regrouper must leave them alone.
  describe('FixedArray regrouping — marker guard', () => {
    const HAND_NAMED_SOURCE = `
      import { StatefulSmartContract } from 'runar-lang';
      export class Scores extends StatefulSmartContract {
        user__0: bigint;
        user__1: bigint;
        user__2: bigint;
        constructor(user__0: bigint, user__1: bigint, user__2: bigint) {
          super(user__0, user__1, user__2);
        }
        public bump(): void {
          this.user__0 = this.user__0 + 1n;
          this.user__1 = this.user__1 + 1n;
          this.user__2 = this.user__2 + 1n;
        }
      }`;

    it('keeps hand-named `user__0/1/2` properties as separate state fields', () => {
      const artifact = assemble(HAND_NAMED_SOURCE);
      const fields = artifact.stateFields ?? [];
      expect(fields.map(f => f.name)).toEqual(['user__0', 'user__1', 'user__2']);
      // None of them should carry a `fixedArray` annotation.
      for (const f of fields) {
        expect(f.fixedArray).toBeUndefined();
      }
    });

    it('keeps hand-named constructor params as separate ABI params', () => {
      const artifact = assemble(HAND_NAMED_SOURCE);
      const params = artifact.abi.constructor.params;
      expect(params.map(p => p.name)).toEqual(['user__0', 'user__1', 'user__2']);
      for (const p of params) {
        expect(p.fixedArray).toBeUndefined();
      }
    });
  });
});
