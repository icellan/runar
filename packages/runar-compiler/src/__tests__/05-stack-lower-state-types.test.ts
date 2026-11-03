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
 *
 * F-291: the five `it(...).not.toThrow()` tests below (plus a sixth,
 * `05-stack-lower.test.ts`'s "compiles a contract with multiple ByteString
 * state fields", duplicated and strengthened here) only prove the pass
 * doesn't throw — they pass identically whether `lowerDeserializeState`
 * (05-stack-lower.ts) extracts the right number of bytes for the field or
 * the wrong one, whether it applies `OP_BIN2NUM` to a numeric field or not,
 * and whether the multi-property decode loop checks the last ByteString
 * field for trailing garbage or silently drops it. The tests added after
 * each one pin the exact Stack-IR opcode/operand sequence
 * `lowerDeserializeState` emits for a mutable property of each shape — the
 * deserialize-side field extractor (`OP_SIZE <width> OP_SUB OP_SPLIT nip`,
 * 05-stack-lower.ts "Extract last stateLen bytes"), for the three
 * fixed-width byte shapes the write-side width guard N-045 injects before
 * the continuation commit (`OP_SIZE <width> OP_NUMEQUALVERIFY`), and for the
 * two-ByteString-field shape the N-044 exact-consumption check
 * (`push 0 OP_EQUALVERIFY`) on the last field. Each one is proven red/green
 * by hand against a one-line mutation of the production code it is meant to
 * catch (see the comment on each test); none of the six pre-existing
 * `not.toThrow()` tests go red under any of those mutations.
 *
 * What none of this proves: that the bytes these opcodes compute are
 * correct Bitcoin Script against a real transaction — that is proven,
 * independently, by SDK-level execution tests against @bsv/sdk's `Spend`:
 * `packages/runar-testing/src/__tests__/n045-state-fixed-width-spend.test.ts`
 * (Ripemd160/P256Point/P384Point width guards, all 7 tiers, both fold
 * modes), `f035-rabin-state-spend.test.ts` (RabinSig/RabinPubKey, all 7
 * tiers x 2 fold modes, hand-derived expected bytes), and
 * `curve-point-state-roundtrip.test.ts` (P256Point/P384Point round-tripped
 * through a real spend). This file's job is the compiler-unit layer those
 * don't touch: pinning what THIS pass (05-stack-lower.ts) emits, so a
 * regression here is caught before it ever reaches a spend-level test.
 */
import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import type { ContractNode, StackOp, StackProgram } from '../ir/index.js';

function compileToStack(source: string): StackProgram {
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

function findMethodOps(program: StackProgram, name: string): StackOp[] {
  const method = program.methods.find(m => m.name === name);
  if (!method) {
    throw new Error(`Stack method '${name}' not found. Available: ${program.methods.map(m => m.name).join(', ')}`);
  }
  return flattenOps(method.ops);
}

function flattenOps(ops: StackOp[]): StackOp[] {
  const result: StackOp[] = [];
  for (const op of ops) {
    if (op.op === 'if') {
      result.push(op);
      result.push(...flattenOps(op.then));
      if (op.else) result.push(...flattenOps(op.else));
    } else {
      result.push(op);
    }
  }
  return result;
}

/**
 * Index of the `OP_SIZE` that starts the deserialize_state fixed-width field
 * extractor `OP_SIZE <width> OP_SUB OP_SPLIT nip` (05-stack-lower.ts
 * `lowerDeserializeState`, step "Extract last stateLen bytes"), or -1.
 * `nip` (not `drop`) distinguishes this occurrence from the two earlier
 * `OP_SIZE <n> OP_SUB OP_SPLIT drop` steps in the same function that trim the
 * preimage's fixed header/tail and are unrelated to this property's width.
 */
function findDeserializeExtract(ops: StackOp[], width: bigint): number {
  for (let i = 0; i + 4 < ops.length; i++) {
    const a = ops[i]!, b = ops[i + 1]!, c = ops[i + 2]!, d = ops[i + 3]!, e = ops[i + 4]!;
    if (
      a.op === 'opcode' && a.code === 'OP_SIZE' &&
      b.op === 'push' && b.value === width &&
      c.op === 'opcode' && c.code === 'OP_SUB' &&
      d.op === 'opcode' && d.code === 'OP_SPLIT' &&
      e.op === 'nip'
    ) {
      return i;
    }
  }
  return -1;
}

/**
 * Index of the N-045 write-side width guard `OP_SIZE <width>
 * OP_NUMEQUALVERIFY` that `lowerDeserializeState`'s sibling continuation
 * writer injects before committing a fixed-width mutable field, or -1.
 */
function findWidthGuard(ops: StackOp[], width: bigint): number {
  for (let i = 0; i + 2 < ops.length; i++) {
    const a = ops[i]!, b = ops[i + 1]!, c = ops[i + 2]!;
    if (
      a.op === 'opcode' && a.code === 'OP_SIZE' &&
      b.op === 'push' && b.value === width &&
      c.op === 'opcode' && c.code === 'OP_NUMEQUALVERIFY'
    ) {
      return i;
    }
  }
  return -1;
}

describe('Pass 5: Stack Lower — stateful property types', () => {
  it('lowers stateful Ripemd160 property (20-byte fixed)', () => {
    expect(() => compileToStack(buildStateful('Ripemd160'))).not.toThrow();
  });

  it('Ripemd160: deserialize_state extracts exactly 20 raw bytes (no BIN2NUM) and the continuation is width-guarded at 20', () => {
    // Two mutations this test catches and the `not.toThrow()` test above
    // does not — both verified by hand (mutate, run, confirm red; revert,
    // confirm green; `not.toThrow()` stays green throughout both):
    //  1. In `lowerDeserializeState` (05-stack-lower.ts), change
    //     `case 'Ripemd160': propSizes.push(20);` to `push(21)`: the pass
    //     still compiles, it just slices one byte too many out of the
    //     preimage's scriptCode for this field.
    //  2. In `fixedWidthStateBytes` (05-stack-lower.ts, the single source of
    //     truth `emitFixedWidthStateCheck`/N-045 reads for the write-side
    //     guard), change `case 'Ripemd160': return 20;` to `return 21`: the
    //     `OP_SIZE 20 OP_NUMEQUALVERIFY` guard before the continuation
    //     commit silently becomes `OP_SIZE 21 ...` instead.
    const ops = findMethodOps(compileToStack(buildStateful('Ripemd160')), 'update');
    const extractAt = findDeserializeExtract(ops, 20n);
    expect(extractAt, 'OP_SIZE 20 OP_SUB OP_SPLIT nip (deserialize_state extractor)').toBeGreaterThanOrEqual(0);
    // A byte-shaped field must not be numerically decoded: BIN2NUM would
    // strip a leading sign/zero byte and corrupt the 20-byte hash.
    const next = ops[extractAt + 5];
    expect(next && next.op === 'opcode' && next.code === 'OP_BIN2NUM', String(next?.op) + (next && 'code' in next ? ':' + (next as { code?: string }).code : '')).toBe(false);
    expect(findWidthGuard(ops, 20n), 'OP_SIZE 20 OP_NUMEQUALVERIFY (continuation width guard)').toBeGreaterThanOrEqual(0);
  });

  it('lowers stateful P256Point property (64-byte fixed)', () => {
    expect(() => compileToStack(buildStateful('P256Point'))).not.toThrow();
  });

  it('P256Point: deserialize_state extracts exactly 64 raw bytes (no BIN2NUM) and the continuation is width-guarded at 64', () => {
    // Same two mutations as Ripemd160 above, verified the same way:
    // `propSizes.push(64)` -> `push(63)` in `lowerDeserializeState`, and
    // `fixedWidthStateBytes`'s `case 'P256Point': return 64;` -> `return 63`.
    // Both still compile; `not.toThrow()` stays green, this test goes red.
    const ops = findMethodOps(compileToStack(buildStateful('P256Point')), 'update');
    const extractAt = findDeserializeExtract(ops, 64n);
    expect(extractAt, 'OP_SIZE 64 OP_SUB OP_SPLIT nip (deserialize_state extractor)').toBeGreaterThanOrEqual(0);
    const next = ops[extractAt + 5];
    expect(next && next.op === 'opcode' && next.code === 'OP_BIN2NUM', String(next?.op) + (next && 'code' in next ? ':' + (next as { code?: string }).code : '')).toBe(false);
    expect(findWidthGuard(ops, 64n), 'OP_SIZE 64 OP_NUMEQUALVERIFY (continuation width guard)').toBeGreaterThanOrEqual(0);
  });

  it('lowers stateful P384Point property (96-byte fixed)', () => {
    expect(() => compileToStack(buildStateful('P384Point'))).not.toThrow();
  });

  it('P384Point: deserialize_state extracts exactly 96 raw bytes (no BIN2NUM) and the continuation is width-guarded at 96', () => {
    // Same two mutations as Ripemd160 above, verified the same way:
    // `propSizes.push(96)` -> `push(95)` in `lowerDeserializeState`, and
    // `fixedWidthStateBytes`'s `case 'P384Point': return 96;` -> `return 95`.
    // Both still compile; `not.toThrow()` stays green, this test goes red.
    const ops = findMethodOps(compileToStack(buildStateful('P384Point')), 'update');
    const extractAt = findDeserializeExtract(ops, 96n);
    expect(extractAt, 'OP_SIZE 96 OP_SUB OP_SPLIT nip (deserialize_state extractor)').toBeGreaterThanOrEqual(0);
    const next = ops[extractAt + 5];
    expect(next && next.op === 'opcode' && next.code === 'OP_BIN2NUM', String(next?.op) + (next && 'code' in next ? ':' + (next as { code?: string }).code : '')).toBe(false);
    expect(findWidthGuard(ops, 96n), 'OP_SIZE 96 OP_NUMEQUALVERIFY (continuation width guard)').toBeGreaterThanOrEqual(0);
  });

  it('lowers stateful RabinSig property (8-byte numeric)', () => {
    expect(() => compileToStack(buildStateful('RabinSig'))).not.toThrow();
  });

  it('RabinSig: deserialize_state extracts 8 bytes and converts them with OP_BIN2NUM', () => {
    // Mutation this test catches and the `not.toThrow()` test above does
    // not: in `splitFixedStateFields`'s single-property branch
    // (05-stack-lower.ts), the numeric-type guard is repeated as
    // `prop.type === 'bigint' || prop.type === 'boolean' ||
    // prop.type === 'RabinSig' || prop.type === 'RabinPubKey'` in four
    // separate places in this file; drop `|| prop.type === 'RabinSig'` from
    // just the single-property branch and the pass still compiles — it
    // simply leaves a RabinSig field as raw bytes instead of a script
    // number, so every comparison/arithmetic the author writes against it
    // (and the next continuation's OP_NUM2BIN re-encoding of it) silently
    // operates on the wrong representation. `not.toThrow()` cannot see a
    // missing OP_BIN2NUM; this test does.
    const ops = findMethodOps(compileToStack(buildStateful('RabinSig')), 'update');
    const extractAt = findDeserializeExtract(ops, 8n);
    expect(extractAt, 'OP_SIZE 8 OP_SUB OP_SPLIT nip (deserialize_state extractor)').toBeGreaterThanOrEqual(0);
    const next = ops[extractAt + 5];
    expect(next, 'OP_BIN2NUM must follow the extractor for a numeric field').toMatchObject({ op: 'opcode', code: 'OP_BIN2NUM' });
  });

  it('lowers stateful RabinPubKey property (8-byte numeric)', () => {
    expect(() => compileToStack(buildStateful('RabinPubKey'))).not.toThrow();
  });

  it('RabinPubKey: deserialize_state extracts 8 bytes and converts them with OP_BIN2NUM', () => {
    // Same mutation class as RabinSig above, with `|| prop.type ===
    // 'RabinPubKey'` dropped instead. Independent of the RabinSig case
    // because the two are separate disjuncts in the same guard — dropping
    // one leaves the other (and this test) green, which is why both types
    // get their own test rather than one standing in for both.
    const ops = findMethodOps(compileToStack(buildStateful('RabinPubKey')), 'update');
    const extractAt = findDeserializeExtract(ops, 8n);
    expect(extractAt, 'OP_SIZE 8 OP_SUB OP_SPLIT nip (deserialize_state extractor)').toBeGreaterThanOrEqual(0);
    const next = ops[extractAt + 5];
    expect(next, 'OP_BIN2NUM must follow the extractor for a numeric field').toMatchObject({ op: 'opcode', code: 'OP_BIN2NUM' });
  });
});

const MULTI_BYTESTRING_SOURCE = `
  class MultiBS extends StatefulSmartContract {
    title: ByteString;
    body: ByteString;
    constructor(title: ByteString, body: ByteString) { super(title, body); this.title = title; this.body = body; }
    public update(newTitle: ByteString, newBody: ByteString) {
      this.title = newTitle;
      this.body = newBody;
      assert(true);
    }
  }
`;

/**
 * Index of the N-044 exact-consumption check `push 0 OP_EQUALVERIFY` that
 * `emitAssertStateConsumed` (05-stack-lower.ts) emits right after decoding
 * the LAST state field, or -1. Empirically unique in a compiled method: nothing
 * else pushes a literal `0` directly into an `OP_EQUALVERIFY`.
 */
function findAssertStateConsumed(ops: StackOp[]): number {
  for (let i = 0; i + 1 < ops.length; i++) {
    const a = ops[i]!, b = ops[i + 1]!;
    if (a.op === 'push' && a.value === 0n && b.op === 'opcode' && b.code === 'OP_EQUALVERIFY') return i;
  }
  return -1;
}

describe('Pass 5: Stack Lower — multiple variable-length (ByteString) state fields', () => {
  // F-291's sixth under-tested shape: `05-stack-lower.test.ts`'s "ByteString
  // state fields" > "compiles a contract with multiple ByteString state
  // fields" (MultiBS) is guarded ONLY by `not.toThrow()`. A single mutable
  // ByteString field already gets its own N-044 exact-consumption check
  // (line 4199) and its own `push_codesep_index` test — MultiBS, with two,
  // exercises the SEPARATE multi-property decode loop (05-stack-lower.ts
  // lowerDeserializeState, lines ~4206-4264) and nothing in the suite checks
  // that loop's output.
  it('compiles a contract with multiple ByteString state fields', () => {
    expect(() => compileToStack(MULTI_BYTESTRING_SOURCE)).not.toThrow();
  });

  it('two ByteString fields: the last one is N-044 exact-consumption checked', () => {
    // Mutation this test catches and the `not.toThrow()` test above does
    // not — verified by hand: in `lowerDeserializeState`'s multi-property
    // loop (05-stack-lower.ts), replace the
    // `this.emitAssertStateConsumed();` call in the LAST-property
    // variable-length branch (around line 4248) with
    // `this.emitOp({ op: 'drop' }); this.stackMap.pop();` (same net stack
    // effect, so the pass still compiles — removing the call outright throws,
    // because `emitAssertStateConsumed`'s own stack-map bookkeeping is no
    // longer balanced). With that substitution in place, the method silently
    // drops `body`'s trailing remainder instead of asserting it's empty, so a
    // spender can append garbage to the committed state (or a future field,
    // if one is ever added after `body`) with no on-chain rejection; the test
    // above stays green and this one goes red (`findAssertStateConsumed`
    // returns -1). Reverting brings this test back to green. The
    // single-ByteString-field case (`MsgStore` tests above) is unaffected
    // either way — it goes through a different call site (line 4199).
    const ops = findMethodOps(compileToStack(MULTI_BYTESTRING_SOURCE), 'update');
    expect(findAssertStateConsumed(ops), 'push 0 OP_EQUALVERIFY (N-044 exact-consumption check on the last field)').toBeGreaterThanOrEqual(0);
  });
});
