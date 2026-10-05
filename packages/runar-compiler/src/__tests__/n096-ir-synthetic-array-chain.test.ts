/**
 * N-096 — `loadANFFromJSON` refuses a `syntheticArrayChain` the
 * expand-fixed-arrays pass could not have written.
 *
 * The chain arrives from outside the compiler on the IR path. TS assembles no
 * artifact there, so before this rule it compiled the F-105 probe (a property
 * whose chain is 1100 levels deep) without comment, while Go panicked on it
 * and the other tiers split three ways. The cross-tier corpus and the exact
 * diagnostics are in `conformance/negatives/ir-synthetic-array-chain.test.ts`;
 * this file pins the TS loader's side of it.
 *
 * Proves: the probe and a chain one level past the bound are refused at load
 * time with the shared diagnostic; a chain AT the bound and the FixedArray
 * goldens still load. Does not prove: anything about the source path.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadANFFromJSON } from '../index.js';

const REPO = join(__dirname, '../../../..');
const goldenIr = (fixture: string): { properties: Array<Record<string, unknown>> } =>
  JSON.parse(readFileSync(join(REPO, 'conformance/tests', fixture, 'expected-ir.json'), 'utf8'));

const withDeep = (depth: number) => {
  const ir = goldenIr('basic-p2pkh');
  ir.properties.splice(1, 0, {
    name: 'deep',
    type: 'bigint',
    readonly: true,
    syntheticArrayChain: Array.from({ length: depth }, () => ({ base: 'deep', index: 0, length: 1 })),
  });
  return JSON.stringify(ir);
};

describe('N-096: --ir syntheticArrayChain validity (TS loader)', () => {
  it('refuses the F-105 probe (1100 levels) with the shared diagnostic', () => {
    expect(() => loadANFFromJSON(withDeep(1100))).toThrow(
      "IR validation: malformed syntheticArrayChain on property 'deep': 1100 levels exceed the limit of 1023",
    );
  });

  it('refuses 1024 levels and checks the bound before the chain names', () => {
    expect(() => loadANFFromJSON(withDeep(1024))).toThrow(/1024 levels exceed the limit of 1023$/);
  });

  it('accepts a well-formed 1023-level chain (the bound)', () => {
    const ir = goldenIr('fixed-array-index');
    const chain = [];
    let base = 'deep';
    for (let k = 0; k < 1023; k++) {
      chain.push({ base, index: 0, length: 1 });
      base = `${base}__0`;
    }
    ir.properties.push({ name: base, type: 'bigint', readonly: true, initialValue: 7, syntheticArrayChain: chain });
    expect(() => loadANFFromJSON(JSON.stringify(ir))).not.toThrow();
  });

  it('loads every FixedArray golden', () => {
    for (const f of ['fixed-array-index', 'fixed-array-write']) {
      expect(() => loadANFFromJSON(JSON.stringify(goldenIr(f))), f).not.toThrow();
    }
  });
});
