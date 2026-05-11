import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

import { emitVerifyWOTS } from '../passes/wots-codegen.js';
import type { StackOp } from '../ir/index.js';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { emit } from '../passes/06-emit.js';
import { optimizeStackIR } from '../optimizer/peephole.js';

// Pre-extraction baseline: SHA-256 of TS-emitted scriptHex for the
// PostQuantumWOTSNaiveInsecure.runar.sol fixture, captured before
// 05-stack-lower.ts had its inline WOTS+ helpers extracted into
// passes/wots-codegen.ts. Any change to emitted bytes breaks this.
const PREFIX_FROZEN_SCRIPT_SHA256 =
  'd0abd9bf9d6775d0b5dfe40972d066f18ff00f46b5c9a7f2dcef47dd5e9f4895';
const PREFIX_FROZEN_SCRIPT_LEN = 39164;
const PREFIX_FROZEN_SCRIPT_HEAD =
  '007b7b7b01207f6b7b7b7ca87c0000537a517f7c0051807e817660967c60976b7c6b765f7c946b7c6b7c6b7c01207f6b7c7692638c677c52790200007e7c7ea87c687692638c677c52790200017e7c7ea87c687692638c677c52790200027e7c7ea87c68';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WOTS_FIXTURE = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'examples',
  'sol',
  'post-quantum-wots-naive-INSECURE',
  'PostQuantumWOTSNaiveInsecure.runar.sol',
);

describe('wots-codegen module extraction (GAP-001)', () => {
  it('exports emitVerifyWOTS from packages/runar-compiler/src/passes/wots-codegen.ts', () => {
    // Pre-fix this import would resolve to nothing (module did not exist).
    expect(typeof emitVerifyWOTS).toBe('function');
  });

  it('emitVerifyWOTS appends StackOps when invoked with an emit callback', () => {
    const ops: StackOp[] = [];
    emitVerifyWOTS((op) => ops.push(op));
    expect(ops.length).toBeGreaterThan(0);
    // Sanity: WOTS+ verification ends with the bool result on top after
    // dropping pubSeed (final ops in the new module: SWAP, drop).
    const last = ops[ops.length - 1];
    expect(last.op).toBe('drop');
  });

  it('compiling the WOTS+ example produces byte-identical hex to pre-extraction baseline', () => {
    const source = readFileSync(WOTS_FIXTURE, 'utf8');
    const parsed = parse(source, 'PostQuantumWOTSNaiveInsecure.runar.sol');
    expect(parsed.contract).not.toBeNull();
    const contract = parsed.contract!;

    const anf = lowerToANF(contract);
    const stack = lowerToStack(anf);
    for (const meth of stack.methods) meth.ops = optimizeStackIR(meth.ops);
    const r = emit(stack);

    expect(r.scriptHex.length).toBe(PREFIX_FROZEN_SCRIPT_LEN);
    expect(r.scriptHex.slice(0, PREFIX_FROZEN_SCRIPT_HEAD.length)).toBe(
      PREFIX_FROZEN_SCRIPT_HEAD,
    );
    expect(createHash('sha256').update(r.scriptHex).digest('hex')).toBe(
      PREFIX_FROZEN_SCRIPT_SHA256,
    );
  });
});
