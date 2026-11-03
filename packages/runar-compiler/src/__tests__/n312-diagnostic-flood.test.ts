import { describe, it, expect, vi, beforeEach } from 'vitest';

// Which stage should return a flood of diagnostics instead of its real result.
const flood = vi.hoisted(() => ({ stage: '' as '' | 'validate' | 'typecheck' | 'expand' | 'warnings' }));
const N = 200_000;
const many = (label: string, severity: 'error' | 'warning' = 'error') =>
  Array.from({ length: N }, (_, i) => ({ message: `${label} ${i}`, severity }));

vi.mock('../passes/02-validate.js', async (orig) => {
  const m = await orig<typeof import('../passes/02-validate.js')>();
  return {
    ...m,
    validate: (c: Parameters<typeof m.validate>[0]) => {
      if (flood.stage === 'validate') return { errors: many('validate'), warnings: [] };
      if (flood.stage === 'warnings') return { errors: [], warnings: many('vwarn', 'warning') };
      return m.validate(c);
    },
  };
});
vi.mock('../passes/03-typecheck.js', async (orig) => {
  const m = await orig<typeof import('../passes/03-typecheck.js')>();
  return {
    ...m,
    typecheck: (c: Parameters<typeof m.typecheck>[0]) =>
      flood.stage === 'typecheck' ? { errors: many('typecheck'), typedContract: c } : m.typecheck(c),
  };
});
vi.mock('../passes/03b-expand-fixed-arrays.js', async (orig) => {
  const m = await orig<typeof import('../passes/03b-expand-fixed-arrays.js')>();
  return {
    ...m,
    expandFixedArrays: (c: Parameters<typeof m.expandFixedArrays>[0]) =>
      flood.stage === 'expand' ? { contract: c, errors: many('expand') } : m.expandFixedArrays(c),
  };
});

import { compile } from '../index.js';

/**
 * N-312 — compile() appended each stage's diagnostics with `push(...list)`. A
 * list of ~10^5 entries overflows the JS stack, and the stage's catch replaced
 * every diagnostic with "Maximum call stack size exceeded".
 *
 * Proves: for validate (errors and warnings), typecheck and expandFixedArrays,
 * a 200k-entry diagnostic list comes back intact through compile() and no
 * diagnostic is a stack-exhaustion message.
 * Does not prove: that a real source can produce that many diagnostics in each
 * stage (the lists are injected by stubbing the stage), nor anything about a cap.
 */
const SRC = `import { SmartContract, assert } from 'runar-lang';
class C extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public m(y: bigint) { assert(y === this.x); }
}
`;

describe('N-312: compile() keeps a large stage diagnostic list', () => {
  beforeEach(() => { flood.stage = ''; });
  const cases: Array<[typeof flood.stage, string]> = [
    ['validate', 'validate'],
    ['warnings', 'vwarn'],
    ['typecheck', 'typecheck'],
    ['expand', 'expand'],
  ];
  for (const [stage, label] of cases) {
    it(`${stage}: ${N} diagnostics are returned, not replaced by a RangeError`, () => {
      flood.stage = stage;
      const r = compile(SRC, { fileName: 'C.runar.ts' });
      const msgs = r.diagnostics.map((d) => d.message);
      expect(msgs.some((m) => /call stack/i.test(m))).toBe(false);
      expect(msgs.filter((m) => m.startsWith(label + ' ')).length).toBe(N);
      expect(r.success).toBe(stage === 'warnings');
    }, 60_000);
  }
});
