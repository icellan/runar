/**
 * F-002 (CL-BUG-224 / CX-DOC-004) — `compileFromANF` never runs ANF constant
 * folding, but its public API said it did.
 *
 * `CompileFromANFOptions.disableConstantFolding` was documented as "If true,
 * skip the ANF constant folding pass. Default: false (folding enabled)", and
 * the function doc listed "constant-fold (optional)" as a stage. The body has
 * never folded on this entry point (re-folding pre-lowered IR leaves dead
 * operand bindings that stack lowering emits as push+drop, diverging from the
 * fold-OFF goldens and from the Go/Zig `--ir` paths, which also never fold).
 * A caller reading the type — the CLI `--ir` path, the decompiler verifier,
 * the conformance fuzzer's `--anf --fold-on` mode — could not tell that the
 * option does nothing.
 *
 * What this proves:
 *   1. Behaviour: on a program with a foldable `bin_op` over two constants,
 *      the default call, `disableConstantFolding: false` and
 *      `disableConstantFolding: true` all return the same ANF (the `bin_op`
 *      is still there — no ANF folding happened) and byte-identical hex.
 *   2. Documentation: the public JSDoc of the option no longer claims
 *      folding is enabled by default, and says the option is ignored here;
 *      the function doc no longer advertises an optional constant-fold stage.
 *
 * What this does NOT prove:
 *   - Anything about the conformance fuzzer's `--anf --fold-on` gate. That
 *     gate drives every tier through `--ir`, and every tier's IR entry point
 *     ignores the flag, so the gate is still a duplicate of the fold-OFF run.
 *     Fixing that is a cross-tier / harness decision outside this TS-only item.
 *   - That ANF folding on IR input would be correct or desirable; it pins the
 *     current, deliberate no-fold contract only.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compileFromANF } from '../index.js';
import type { ANFProgram } from '../ir/index.js';

/** unlock(x) { assert(x === 2 + 3) } — `2 + 3` is foldable. */
function foldableProgram(): ANFProgram {
  return {
    contractName: 'Foldable',
    properties: [],
    methods: [
      {
        name: 'unlock',
        params: [{ name: 'x', type: 'bigint' }],
        body: [
          { name: 't0', value: { kind: 'load_const', value: 2n } },
          { name: 't1', value: { kind: 'load_const', value: 3n } },
          { name: 't2', value: { kind: 'bin_op', op: '+', left: 't0', right: 't1' } },
          { name: 't3', value: { kind: 'bin_op', op: '===', left: 'x', right: 't2' } },
          { name: 't4', value: { kind: 'assert', value: 't3' } },
        ],
        isPublic: true,
      },
    ],
  };
}

function t2Kind(anf: ANFProgram): string | undefined {
  return anf.methods[0]!.body.find((b) => b.name === 't2')?.value.kind;
}

describe('F-002 compileFromANF: disableConstantFolding is ignored, and documented as such', () => {
  it('no ANF folding happens in any mode; hex is identical across modes', () => {
    const byDefault = compileFromANF(foldableProgram());
    const foldRequested = compileFromANF(foldableProgram(), { disableConstantFolding: false });
    const foldDisabled = compileFromANF(foldableProgram(), { disableConstantFolding: true });

    // Had the ANF folder run, t2 would have become a load_const.
    expect(t2Kind(byDefault.anf)).toBe('bin_op');
    expect(t2Kind(foldRequested.anf)).toBe('bin_op');
    expect(t2Kind(foldDisabled.anf)).toBe('bin_op');

    expect(byDefault.scriptHex).toBe(foldDisabled.scriptHex);
    expect(foldRequested.scriptHex).toBe(foldDisabled.scriptHex);
  });

  const INDEX = resolve(__dirname, '../index.ts');

  it('the public option JSDoc does not claim folding is enabled by default', () => {
    const src = readFileSync(INDEX, 'utf-8');
    const iface = /export interface CompileFromANFOptions \{([\s\S]*?)\n\}/.exec(src);
    expect(iface, 'CompileFromANFOptions interface not found').not.toBeNull();
    const doc = /\/\*\*((?:(?!\*\/)[\s\S])*)\*\/\s*disableConstantFolding\?: boolean;/.exec(iface![1]!);
    expect(doc, 'disableConstantFolding JSDoc not found').not.toBeNull();
    const text = doc![1]!;
    expect(text).not.toMatch(/folding enabled/i);
    expect(text).toMatch(/@deprecated/);
    expect(text).toMatch(/ignored/i);
  });

  it('the compileFromANF doc does not advertise an optional constant-fold stage', () => {
    const src = readFileSync(INDEX, 'utf-8');
    const fnDoc = /\/\*\*((?:(?!\*\/)[\s\S])*)\*\/\s*export function compileFromANF\(/.exec(src);
    expect(fnDoc, 'compileFromANF JSDoc not found').not.toBeNull();
    expect(fnDoc![1]!).not.toMatch(/constant-fold \(optional\)/);
  });
});
