import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { emitVerifyRabinSig, RABIN_PADDING_LIMIT } from '../passes/rabin-codegen.js';
import type { StackOp } from '../ir/index.js';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { emit } from '../passes/06-emit.js';
import { optimizeStackIR } from '../optimizer/peephole.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ORACLE_FIXTURE = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'examples',
  'ts',
  'oracle-price',
  'OraclePriceFeed.runar.ts',
);
const ORACLE_GOLDEN = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'conformance',
  'tests',
  'oracle-price',
  'expected-script.hex',
);

// The fixed Rabin verification opcode sequence (post BUG-010 + BUG-011 +
// F-047 + F-144, 29 ops total): (sig^2 + padding) mod pubKey == SHA256(msg)
// mod pubKey numerically, AND 0 <= padding < 65536, with pubKey, padding and
// sig each read as an unsigned little-endian integer.
// `null` at position 9 marks a push of RABIN_PADDING_LIMIT (65536); each
// 'BYTES:00' entry marks a raw single-zero-byte push (an explicit
// non-negative sign byte — F-144 operand normalization, BUG-011 digest).
const RABIN_OPCODES: (string | null)[] = [
  'BYTES:00', // F-144: pubKey as unsigned
  'OP_CAT',
  'OP_BIN2NUM',
  'OP_SWAP',
  'BYTES:00', // F-144: padding as unsigned
  'OP_CAT',
  'OP_BIN2NUM',
  'OP_DUP',
  'OP_0',
  null, // push 65536 (BUG-010 padding limit)
  'OP_WITHIN',
  'OP_VERIFY',
  'OP_ROT',
  'BYTES:00', // F-144: sig as unsigned
  'OP_CAT',
  'OP_BIN2NUM',
  'OP_DUP',
  'OP_MUL',
  'OP_ADD',
  'OP_OVER', // F-047: keep pubKey for the digest reduction
  'OP_MOD',
  'OP_ROT',
  'OP_SHA256',
  'BYTES:00', // push 0x00 (BUG-011 sign byte for the raw digest)
  'OP_CAT',
  'OP_BIN2NUM',
  'OP_ROT', // F-047: bring pubKey up
  'OP_MOD', // F-047: SHA256(msg) mod pubKey
  'OP_NUMEQUAL',
];

describe('rabin-codegen module extraction (GAP-M1)', () => {
  it('exports emitVerifyRabinSig from passes/rabin-codegen.ts', () => {
    expect(typeof emitVerifyRabinSig).toBe('function');
  });

  it('emits exactly the 29-op Rabin verification sequence (BUG-010 + BUG-011 + F-047 + F-144)', () => {
    const ops: StackOp[] = [];
    emitVerifyRabinSig((op) => ops.push(op));
    expect(ops).toHaveLength(29);
    for (let i = 0; i < ops.length; i++) {
      const expected = RABIN_OPCODES[i];
      const op = ops[i]!;
      if (expected === null) {
        expect(op.op).toBe('push');
        expect((op as Extract<StackOp, { op: 'push' }>).value).toBe(
          RABIN_PADDING_LIMIT,
        );
      } else if (expected === 'BYTES:00') {
        expect(op.op).toBe('push');
        const value = (op as Extract<StackOp, { op: 'push' }>).value;
        expect(value).toBeInstanceOf(Uint8Array);
        expect(Array.from(value as Uint8Array)).toEqual([0x00]);
      } else {
        expect(op.op).toBe('opcode');
        expect((op as Extract<StackOp, { op: 'opcode' }>).code).toBe(expected);
      }
    }
  });

  it('compiling the oracle-price fixture produces byte-identical hex to the conformance golden', () => {
    const source = readFileSync(ORACLE_FIXTURE, 'utf8');
    const parsed = parse(source, 'OraclePriceFeed.runar.ts');
    expect(parsed.contract).not.toBeNull();

    const anf = lowerToANF(parsed.contract!);
    const stack = lowerToStack(anf);
    for (const meth of stack.methods) meth.ops = optimizeStackIR(meth.ops);
    const r = emit(stack);

    const golden = readFileSync(ORACLE_GOLDEN, 'utf8').trim();
    expect(r.scriptHex).toBe(golden);
  });
});
