/**
 * raw_script ANF kind: schema drift gate + optimizer barrier behavior.
 *
 * Pins the ANF kind list against three sync points so a future contributor
 * cannot add a kind in one place but forget another. Also verifies the
 * raw_script node is a hard barrier — the peephole optimizer never rewrites
 * across it, and the EC algebraic optimizer never folds across it.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { optimizeStackIR } from '../optimizer/peephole.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { emit } from '../passes/06-emit.js';
import { foldConstants } from '../optimizer/constant-fold.js';
import { optimizeEC } from '../optimizer/anf-ec.js';
import type { ANFProgram, StackOp } from '../ir/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..', '..', '..', '..');

// ---------------------------------------------------------------------------
// Drift gate: kinds enumerated in three sync points must match
// ---------------------------------------------------------------------------

describe('ANF kind list — sync gate across compiler / schema / JSON', () => {
  const compilerAnfPath = resolve(REPO_ROOT, 'packages/runar-compiler/src/ir/anf-ir.ts');
  const schemaTsPath    = resolve(REPO_ROOT, 'packages/runar-ir-schema/src/anf-ir.ts');
  const schemaJsonPath  = resolve(REPO_ROOT, 'packages/runar-ir-schema/src/schemas/anf-ir.schema.json');

  /** Extract every `kind: '<name>'` literal from a TS source file. */
  function extractTsKinds(path: string): Set<string> {
    const src = readFileSync(path, 'utf8');
    const matches = src.matchAll(/^\s*kind:\s*'([a-z_]+)'/gm);
    const out = new Set<string>();
    for (const m of matches) out.add(m[1]!);
    return out;
  }

  /** Extract every `"const": "<name>"` from the JSON schema (the oneOf discriminator). */
  function extractJsonKinds(path: string): Set<string> {
    const src = readFileSync(path, 'utf8');
    const matches = src.matchAll(/"const":\s*"([a-z_]+)"/g);
    const out = new Set<string>();
    for (const m of matches) out.add(m[1]!);
    return out;
  }

  it('compiler anf-ir.ts and ir-schema anf-ir.ts enumerate the same kinds', () => {
    const a = extractTsKinds(compilerAnfPath);
    const b = extractTsKinds(schemaTsPath);
    expect([...a].sort()).toEqual([...b].sort());
  });

  it('JSON schema oneOf matches the TypeScript ANFValue union', () => {
    const ts = extractTsKinds(compilerAnfPath);
    const json = extractJsonKinds(schemaJsonPath);
    expect([...ts].sort()).toEqual([...json].sort());
  });

  it('raw_script is present in all three sync points', () => {
    const compiler = extractTsKinds(compilerAnfPath);
    const schemaTs = extractTsKinds(schemaTsPath);
    const json     = extractJsonKinds(schemaJsonPath);
    expect(compiler.has('raw_script')).toBe(true);
    expect(schemaTs.has('raw_script')).toBe(true);
    expect(json.has('raw_script')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Stack-lower + emit: raw_script bytes round-trip verbatim
// ---------------------------------------------------------------------------

describe('raw_script → stack-lower → emit', () => {
  it('emits a single raw_bytes StackOp with verbatim bytes', () => {
    const program: ANFProgram = {
      contractName: 'AsmOnly',
      properties: [],
      methods: [
        {
          name: 'unlock',
          params: [],
          isPublic: true,
          body: [
            {
              name: 't0',
              value: { kind: 'raw_script', bytes: '5168', in_arity: 0, out_arity: 1 },
            },
          ],
        },
      ],
    };

    const stack = lowerToStack(program);
    const m = stack.methods.find(m => m.name === 'unlock')!;
    expect(m.ops.length).toBe(1);
    const op = m.ops[0]!;
    expect(op.op).toBe('raw_bytes');
    if (op.op === 'raw_bytes') {
      expect(op.in_arity).toBe(0);
      expect(op.out_arity).toBe(1);
      expect([...op.bytes]).toEqual([0x51, 0x68]);
    }

    const emitted = emit(stack);
    expect(emitted.scriptHex).toBe('5168');
    expect(emitted.scriptAsm).toContain('<raw 2 bytes>');
  });

  it('the bytes survive constant folding + EC optimization unchanged', () => {
    const program: ANFProgram = {
      contractName: 'AsmFolded',
      properties: [],
      methods: [
        {
          name: 'unlock',
          params: [],
          isPublic: true,
          body: [
            { name: 't0', value: { kind: 'raw_script', bytes: 'aa55', in_arity: 0, out_arity: 1 } },
          ],
        },
      ],
    };
    const folded = foldConstants(program);
    const ecOpt = optimizeEC(folded);
    // The body's first binding must remain a raw_script — folding mustn't strip it.
    const body = ecOpt.methods.find(m => m.name === 'unlock')!.body;
    expect(body.length).toBeGreaterThan(0);
    expect(body[0]!.value.kind).toBe('raw_script');
    if (body[0]!.value.kind === 'raw_script') {
      expect(body[0]!.value.bytes).toBe('aa55');
    }
  });
});

// ---------------------------------------------------------------------------
// Peephole barrier: rules must not bridge across raw_bytes
// ---------------------------------------------------------------------------

describe('peephole optimizer — raw_bytes barrier', () => {
  it('does not fuse PUSH + DROP across a raw_bytes boundary', () => {
    // Without the barrier, the peephole rule `PUSH x, DROP → []` would
    // eliminate both the push and the drop, dropping useful bytes from the
    // surrounding context. The barrier must preserve all three ops.
    const ops: StackOp[] = [
      { op: 'push', value: 7n },
      { op: 'raw_bytes', bytes: new Uint8Array([0xaa]), in_arity: 0, out_arity: 0 },
      { op: 'drop' },
    ];
    const out = optimizeStackIR(ops);
    expect(out.length).toBe(3);
    expect(out[0]!.op).toBe('push');
    expect(out[1]!.op).toBe('raw_bytes');
    expect(out[2]!.op).toBe('drop');
  });

  it('does not collapse SWAP+SWAP across raw_bytes', () => {
    const ops: StackOp[] = [
      { op: 'swap' },
      { op: 'raw_bytes', bytes: new Uint8Array([0xbb]), in_arity: 0, out_arity: 0 },
      { op: 'swap' },
    ];
    const out = optimizeStackIR(ops);
    expect(out.length).toBe(3);
    expect(out[0]!.op).toBe('swap');
    expect(out[1]!.op).toBe('raw_bytes');
    expect(out[2]!.op).toBe('swap');
  });

  it('still applies peephole rules on either side of a raw_bytes', () => {
    // Confirms the barrier is targeted — code BEFORE and AFTER the
    // raw_bytes is still optimized by the rules that don't span it.
    // Before: PUSH 0, DROP → eliminated. After: PUSH 7, DROP → eliminated.
    // The raw_bytes itself stays put.
    const ops: StackOp[] = [
      { op: 'push', value: 0n },
      { op: 'drop' },
      { op: 'raw_bytes', bytes: new Uint8Array([0xcc]), in_arity: 0, out_arity: 0 },
      { op: 'push', value: 7n },
      { op: 'drop' },
    ];
    const out = optimizeStackIR(ops);
    expect(out.length).toBe(1);
    expect(out[0]!.op).toBe('raw_bytes');
  });
});
