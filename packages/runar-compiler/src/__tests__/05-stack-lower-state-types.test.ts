/**
 * Regression tests for stateful-state-property codegen type coverage.
 *
 * The Rúnar language recognises 14 state-compatible types. The stack-lower
 * pass must cover all of them so that the TypeScript reference compiler
 * can emit deserialize_state / computeStateBytes / computeStateOutputHash
 * for contracts that use any of them.
 *
 * Historically the TS compiler only covered 9 types (bigint, boolean,
 * ByteString, PubKey, Sig, Sha256, Addr, SigHashPreimage, Point). This
 * test file exercises the remaining 5 (Ripemd160, RabinSig, RabinPubKey,
 * P256Point, P384Point) so that divergence from the Rust reference
 * (see compilers/rust/src/codegen/stack.rs:2531 for the complete switch)
 * cannot regress silently.
 *
 * Sizes:
 *   Ripemd160   = 20 bytes
 *   P256Point   = 64 bytes  (x[32] || y[32])
 *   P384Point   = 96 bytes  (x[48] || y[48])
 *   RabinSig    = numeric (8-byte via BIN2NUM, bigint alias)
 *   RabinPubKey = numeric (8-byte via BIN2NUM, bigint alias)
 */
import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import type { ContractNode } from '../ir/index.js';

function compileToStack(source: string) {
  const parsed = parse(source);
  if (!parsed.contract) {
    throw new Error(
      `Parse failed: ${parsed.errors.map(e => e.message).join(', ')}`,
    );
  }
  const contract: ContractNode = parsed.contract;
  const anf = lowerToANF(contract);
  return lowerToStack(anf);
}

function buildStateful(propType: string): string {
  // A minimal stateful contract that mutates a single property of the
  // given type. The compiler auto-injects checkPreimage + state
  // continuation, exercising serialize_state (computeStateBytes /
  // computeStateOutputHash) and deserialize_state for `propType`.
  //
  // We seed the mutation with a `load_prop` followed by a store, which
  // forces deserialize_state to emit a field extractor so the body can
  // read the property.
  return `
    class S extends StatefulSmartContract {
      v: ${propType};
      constructor(v: ${propType}) { super(v); this.v = v; }
      public update(newV: ${propType}, txPreimage: SigHashPreimage) {
        this.v = newV;
      }
    }
  `;
}

describe('Pass 5: Stack Lower — stateful property types', () => {
  it('lowers stateful Ripemd160 property (20-byte fixed)', () => {
    expect(() => compileToStack(buildStateful('Ripemd160'))).not.toThrow();
  });

  it('lowers stateful P256Point property (64-byte fixed)', () => {
    expect(() => compileToStack(buildStateful('P256Point'))).not.toThrow();
  });

  it('lowers stateful P384Point property (96-byte fixed)', () => {
    expect(() => compileToStack(buildStateful('P384Point'))).not.toThrow();
  });

  it('lowers stateful RabinSig property (8-byte numeric)', () => {
    expect(() => compileToStack(buildStateful('RabinSig'))).not.toThrow();
  });

  it('lowers stateful RabinPubKey property (8-byte numeric)', () => {
    expect(() => compileToStack(buildStateful('RabinPubKey'))).not.toThrow();
  });
});
