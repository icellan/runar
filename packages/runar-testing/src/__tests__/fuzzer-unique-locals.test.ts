/**
 * The generators must never declare the same local twice in one scope.
 *
 * `spec/grammar.md` forbids re-declaring a variable in the same scope. The
 * generators drew each declared local's name independently from `local0..99`,
 * so two declarations in one method could collide (`const local23 = a;
 * const local23 = b;`). That program is invalid Rúnar, and the surfaces
 * disagree on what it means: TS/Go/Rust/Zig/Java lower the second
 * declaration as a fresh shadowing binding (`local23@1`), while Python and
 * Ruby cannot express a redeclaration at all and lower it as a rebind
 * (`local23`). The emitted script is identical, but the nightly ANF
 * differential (`--ir` without `--hex`) reported it as a ts-vs-python/ruby
 * mismatch (seed 1088847055: FuzzContract3/25/28).
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  arbGeneratedContract,
  arbGeneratedStatefulContract,
  arbContract,
  type GeneratedContract,
} from '../fuzzer/index.js';
import type { Stmt } from '../fuzzer/contract-ir.js';

const SEED = 1088847055;
const RUNS = 1000;

/** Names declared more than once in the same block (recursing into nested blocks). */
function duplicateDecls(body: Stmt[]): string[] {
  const seen = new Set<string>();
  const dups: string[] = [];
  for (const s of body) {
    if (s.kind === 'var_decl') {
      if (seen.has(s.name)) dups.push(s.name);
      seen.add(s.name);
    } else if (s.kind === 'if') {
      dups.push(...duplicateDecls(s.then));
      if (s.else_) dups.push(...duplicateDecls(s.else_));
    } else if (s.kind === 'for') {
      dups.push(...duplicateDecls(s.body));
    }
  }
  return dups;
}

function contractDuplicates(c: GeneratedContract): string[] {
  return c.methods.flatMap((m) =>
    duplicateDecls(m.body).map((n) => `${c.name}.${m.name}: ${n}`),
  );
}

describe('fuzzer generators: no same-scope local redeclaration', () => {
  it('arbGeneratedContract', () => {
    const dups = fc
      .sample(arbGeneratedContract, { numRuns: RUNS, seed: SEED })
      .flatMap(contractDuplicates);
    expect(dups).toEqual([]);
  });

  it('arbGeneratedStatefulContract', () => {
    const dups = fc
      .sample(arbGeneratedStatefulContract, { numRuns: RUNS, seed: SEED })
      .flatMap(contractDuplicates);
    expect(dups).toEqual([]);
  });

  it('arbContract (string generator)', () => {
    const dups: string[] = [];
    for (const src of fc.sample(arbContract, { numRuns: RUNS, seed: SEED })) {
      for (const method of src.split(/\n {2}public /).slice(1)) {
        const names = [...method.matchAll(/\blet (\w+):/g)].map((m) => m[1]!);
        const seen = new Set<string>();
        for (const n of names) {
          if (seen.has(n)) dups.push(n);
          seen.add(n);
        }
      }
    }
    expect(dups).toEqual([]);
  });
});
