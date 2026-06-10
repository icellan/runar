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

// The fixed Rabin verification opcode sequence (post BUG-010, 15 ops total):
// (sig^2 + padding) mod pubKey == SHA256(msg) AND 0 <= padding < 65536.
// `null` at position 3 marks a push of RABIN_PADDING_LIMIT (65536), not an opcode.
const RABIN_OPCODES: (string | null)[] = [
  'OP_SWAP',
  'OP_DUP',
  'OP_0',
  null, // push 65536 (BUG-010 padding limit)
  'OP_WITHIN',
  'OP_VERIFY',
  'OP_ROT',
  'OP_DUP',
  'OP_MUL',
  'OP_ADD',
  'OP_SWAP',
  'OP_MOD',
  'OP_SWAP',
  'OP_SHA256',
  'OP_EQUAL',
];

describe('rabin-codegen module extraction (GAP-M1)', () => {
  it('exports emitVerifyRabinSig from passes/rabin-codegen.ts', () => {
    expect(typeof emitVerifyRabinSig).toBe('function');
  });

  it('emits exactly the 15-opcode Rabin verification sequence (BUG-010)', () => {
    const ops: StackOp[] = [];
    emitVerifyRabinSig((op) => ops.push(op));
    expect(ops).toHaveLength(15);
    for (let i = 0; i < ops.length; i++) {
      const expected = RABIN_OPCODES[i];
      const op = ops[i]!;
      if (expected === null) {
        expect(op.op).toBe('push');
        expect((op as Extract<StackOp, { op: 'push' }>).value).toBe(
          RABIN_PADDING_LIMIT,
        );
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
