/**
 * Script-byte cost model — exactness tests.
 *
 * The cost model exists so optimizer passes can compare two candidate
 * lowerings by the metric that actually matters (serialized locking-script
 * bytes) BEFORE emitting either. That is only useful if the estimate is not
 * an estimate at all: the contract asserted here is
 *
 *     estimateScriptBytes(ops) === emitMethod({ ops, ... }).scriptHex.length / 2
 *
 * for every op sequence the compiler can produce. The sweep below runs that
 * equality over every conformance fixture, so the model is a CHECKED MIRROR
 * of `06-emit.ts` rather than a second, drifting opinion about encoding.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { join, resolve } from 'path';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { emitMethod } from '../passes/06-emit.js';
import { optimizeStackIR } from '../optimizer/peephole.js';
import { sizeOfStackOp, estimateScriptBytes } from '../metrics/cost-model.js';
import type { StackOp } from '../ir/index.js';

const CONFORMANCE_DIR = join(__dirname, '..', '..', '..', '..', 'conformance', 'tests');

/** Emit a bare op list through the real emitter and return its byte length. */
function emittedBytes(ops: StackOp[]): number {
  const result = emitMethod({ name: 'probe', ops, maxStackDepth: 0 });
  return result.scriptHex.length / 2;
}

/** Assert the model agrees with the emitter for one op sequence. */
function expectExact(ops: StackOp[]): void {
  expect(estimateScriptBytes(ops)).toBe(emittedBytes(ops));
}

// ---------------------------------------------------------------------------
// Per-op-kind units
// ---------------------------------------------------------------------------

describe('sizeOfStackOp', () => {
  it('costs a named opcode at one byte', () => {
    expect(sizeOfStackOp({ op: 'opcode', code: 'OP_ADD' })).toBe(1);
  });

  it('throws on an unknown opcode rather than silently costing zero', () => {
    expect(() => sizeOfStackOp({ op: 'opcode', code: 'OP_NOT_A_REAL_OPCODE' })).toThrow(
      /OP_NOT_A_REAL_OPCODE/,
    );
  });

  it.each([
    ['dup'], ['swap'], ['drop'], ['nip'], ['over'], ['rot'], ['tuck'],
  ] as const)('costs the nullary shuffle %s at one byte', (op) => {
    expect(sizeOfStackOp({ op } as StackOp)).toBe(1);
  });

  it('costs pick/roll at one byte — the depth push is a separate op', () => {
    // bringToTop emits `push(depth)` and `pick{depth}` as TWO ops; counting
    // the depth inside the pick would double-charge it.
    expect(sizeOfStackOp({ op: 'pick', depth: 40 })).toBe(1);
    expect(sizeOfStackOp({ op: 'roll', depth: 40 })).toBe(1);
  });

  it('costs placeholder and codesep-index at one byte each', () => {
    expect(sizeOfStackOp({ op: 'placeholder', paramIndex: 0, paramName: 'x' })).toBe(1);
    expect(sizeOfStackOp({ op: 'push_codesep_index' })).toBe(1);
  });

  it('costs raw_bytes at its verbatim length', () => {
    const bytes = new Uint8Array([0x51, 0x52, 0x93]);
    expect(sizeOfStackOp({ op: 'raw_bytes', bytes, in_arity: 0, out_arity: 1 })).toBe(3);
  });

  describe('push encoding', () => {
    it.each([
      [0n, 1],       // OP_0
      [1n, 1],       // OP_1
      [16n, 1],      // OP_16
      [-1n, 1],      // OP_1NEGATE
      [17n, 2],      // len prefix + 1 byte
      [127n, 2],
      [128n, 3],     // sign byte forces 2 data bytes
      [-128n, 3],
      [65535n, 4],
    ])('costs push(%s) at %i bytes', (value, want) => {
      expect(sizeOfStackOp({ op: 'push', value })).toBe(want);
    });

    it('costs the P-256 field prime push at 34 bytes', () => {
      // 32 magnitude bytes + 1 sign byte + 1 length prefix. This single push
      // accounts for 680,850 of p256-wallet's 958,792 bytes.
      const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
      expect(sizeOfStackOp({ op: 'push', value: p })).toBe(34);
    });

    it('costs byte-array pushes across the PUSHDATA boundaries', () => {
      expect(sizeOfStackOp({ op: 'push', value: new Uint8Array(0) })).toBe(1);
      expect(sizeOfStackOp({ op: 'push', value: new Uint8Array(1).fill(0xaa) })).toBe(2);
      expect(sizeOfStackOp({ op: 'push', value: new Uint8Array(75).fill(0xaa) })).toBe(76);
      expect(sizeOfStackOp({ op: 'push', value: new Uint8Array(76).fill(0xaa) })).toBe(78);
      expect(sizeOfStackOp({ op: 'push', value: new Uint8Array(255).fill(0xaa) })).toBe(257);
      expect(sizeOfStackOp({ op: 'push', value: new Uint8Array(256).fill(0xaa) })).toBe(259);
    });

    it('costs boolean pushes like the emitter encodes them', () => {
      expectExact([{ op: 'push', value: true }]);
      expectExact([{ op: 'push', value: false }]);
    });
  });

  describe('if', () => {
    it('costs OP_IF + body + OP_ENDIF when there is no else arm', () => {
      const op: StackOp = { op: 'if', then: [{ op: 'opcode', code: 'OP_ADD' }] };
      expect(sizeOfStackOp(op)).toBe(3);
      expectExact([op]);
    });

    it('costs OP_IF + then + OP_ELSE + else + OP_ENDIF', () => {
      const op: StackOp = {
        op: 'if',
        then: [{ op: 'opcode', code: 'OP_ADD' }],
        else: [{ op: 'push', value: 0n }],
      };
      expect(sizeOfStackOp(op)).toBe(5);
      expectExact([op]);
    });

    it('recurses into nested arms', () => {
      const inner: StackOp = { op: 'if', then: [{ op: 'opcode', code: 'OP_ADD' }] };
      const outer: StackOp = { op: 'if', then: [inner], else: [inner] };
      // outer IF(1) + inner(3) + ELSE(1) + inner(3) + ENDIF(1)
      expect(sizeOfStackOp(outer)).toBe(9);
      expectExact([outer]);
    });

    it('omits OP_ELSE for an empty else arm, matching emitIf', () => {
      const op: StackOp = { op: 'if', then: [{ op: 'opcode', code: 'OP_ADD' }], else: [] };
      expect(sizeOfStackOp(op)).toBe(3);
      expectExact([op]);
    });
  });
});

// ---------------------------------------------------------------------------
// The real contract: exact agreement with the emitter, over every fixture
// ---------------------------------------------------------------------------

interface SourceConfig {
  sources?: Record<string, string>;
}

function tsSourceFor(fixture: string): string | null {
  const configFile = join(CONFORMANCE_DIR, fixture, 'source.json');
  if (!existsSync(configFile)) return null;
  const config = JSON.parse(readFileSync(configFile, 'utf-8')) as SourceConfig;
  const rel = config.sources?.['.runar.ts'];
  if (rel === undefined) return null;
  const abs = resolve(CONFORMANCE_DIR, fixture, rel);
  if (!existsSync(abs)) throw new Error(`source.json points at a missing file: ${abs}`);
  return abs;
}

const FIXTURES = readdirSync(CONFORMANCE_DIR, { withFileTypes: true })
  .filter(e => e.isDirectory())
  .map(e => e.name)
  .filter(name => tsSourceFor(name) !== null)
  .sort();

describe('estimateScriptBytes matches the emitter exactly', () => {
  it('found the conformance corpus', () => {
    expect(FIXTURES.length).toBeGreaterThan(50);
  });

  it.each(FIXTURES)('%s', (fixture) => {
    const path = tsSourceFor(fixture)!;
    const source = readFileSync(path, 'utf-8');
    const parsed = parse(source, path);
    if (!parsed.contract) {
      throw new Error(`parse failed for ${fixture}: ${parsed.errors.map(e => e.message).join(', ')}`);
    }
    const stack = lowerToStack(lowerToANF(parsed.contract));

    for (const method of stack.methods) {
      // Both before and after peephole: the model must be exact on any op
      // sequence the pipeline can hand the emitter, not just the final one.
      expect(estimateScriptBytes(method.ops)).toBe(emitMethod(method).scriptHex.length / 2);

      const optimized = { ...method, ops: optimizeStackIR(method.ops) };
      expect(estimateScriptBytes(optimized.ops)).toBe(
        emitMethod(optimized).scriptHex.length / 2,
      );
    }
  });
});
