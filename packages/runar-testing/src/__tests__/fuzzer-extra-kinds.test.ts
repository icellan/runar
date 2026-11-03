/**
 * N-400 — REACHABILITY gate for the four ANF kinds no fuzzer used to reach:
 * `add_raw_output`, `add_data_output`, `method_call` (a call to a PRIVATE
 * method) and `raw_script` (`asm({...})` in an `UnsafeSmartContract`).
 *
 * `withExtraKinds(base)` is the opt-in generator option (the default
 * distributions are unchanged, which keeps every fixed-seed CI corpus
 * byte-stable). Every assertion is made on the generated IR — the `Stmt`
 * trees and the `visibility` of the methods — at a FIXED seed, never on a
 * label.
 *
 * PROVES:
 *   - at the fixed seed the stateful option draws every one of
 *     `add_raw_output`, `add_data_output` and `method_call` at least once, and
 *     the stateless option draws `method_call` and `raw_script` (the latter
 *     only in a contract whose parentClass is `UnsafeSmartContract`, ending a
 *     public method with out_arity 1);
 *   - every `method_call` targets a method that exists and is private, with a
 *     matching arity, and every output statement reads a declared ByteString
 *     parameter;
 *   - each of the seven renderers spells the new statements in its own
 *     surface form;
 *   - the real TS compiler accepts EVERY sampled program (the generator must
 *     feed valid Rúnar, so a rejection is a generator bug, never a compiler
 *     bug), fold-OFF, and a private helper changes the emitted bytes;
 *   - the DEFAULT arbitraries still never draw the new kinds.
 * DOES NOT PROVE: that the six native tiers accept these programs or agree on
 * their bytes — that is what `--ir --hex --extra-kinds` checks (see
 * `conformance/fuzzer/README.md`); nor that the scripts are spendable.
 */
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { compile } from 'runar-compiler';
import {
  arbGeneratedContract,
  arbGeneratedStatefulContract,
  withExtraKinds,
  RENDERERS,
  FORMAT_EXTENSIONS,
  type GeneratedContract,
  type Stmt,
} from '../fuzzer/index.js';

const SEED = 424242;
const N = 80;
const STATEFUL = fc.sample(withExtraKinds(arbGeneratedStatefulContract), { numRuns: N, seed: SEED });
const STATELESS = fc.sample(withExtraKinds(arbGeneratedContract), { numRuns: N, seed: SEED });

function walk(stmts: Stmt[], out: Stmt[] = []): Stmt[] {
  for (const s of stmts) {
    out.push(s);
    if (s.kind === 'if') {
      walk(s.then, out);
      if (s.else_) walk(s.else_, out);
    } else if (s.kind === 'for') walk(s.body, out);
  }
  return out;
}
const allStmts = (c: GeneratedContract): Stmt[] => c.methods.flatMap((m) => walk(m.body));
const has = (c: GeneratedContract, kind: Stmt['kind']): boolean => allStmts(c).some((s) => s.kind === kind);

describe('N-400: withExtraKinds draws the previously unreachable kinds', () => {
  it('stateful: add_raw_output, add_data_output and method_call all appear', () => {
    expect(STATEFUL.filter((c) => has(c, 'add_raw_output')).length).toBeGreaterThan(0);
    expect(STATEFUL.filter((c) => has(c, 'add_data_output')).length).toBeGreaterThan(0);
    expect(STATEFUL.filter((c) => has(c, 'method_call')).length).toBeGreaterThan(0);
  });

  it('stateless: method_call and raw_script appear and no output intrinsic is drawn', () => {
    expect(STATELESS.filter((c) => has(c, 'method_call')).length).toBeGreaterThan(0);
    const raw = STATELESS.filter((c) => has(c, 'raw_script'));
    expect(raw.length).toBeGreaterThan(0);
    for (const c of raw) {
      expect(c.parentClass).toBe('UnsafeSmartContract');
      for (const m of c.methods.filter((x) => x.visibility === 'public')) {
        const last = m.body[m.body.length - 1]!;
        // A public method either still ends in its assert or ends in the asm.
        expect(['assert', 'raw_script']).toContain(last.kind);
        if (last.kind === 'raw_script') expect(last.outArity).toBe(1n);
      }
    }
    for (const c of STATELESS.filter((x) => !has(x, 'raw_script'))) expect(c.parentClass).toBe('SmartContract');
    for (const c of STATELESS) {
      expect(has(c, 'add_raw_output')).toBe(false);
      expect(has(c, 'add_data_output')).toBe(false);
    }
  });

  it('every method_call targets an existing private method of the same arity; outputs read a ByteString param', () => {
    for (const c of [...STATEFUL, ...STATELESS]) {
      for (const m of c.methods) {
        for (const s of walk(m.body)) {
          if (s.kind === 'method_call') {
            const target = c.methods.find((t) => t.name === s.name);
            expect(target, `${c.name}: ${s.name} must exist`).toBeDefined();
            expect(target!.visibility).toBe('private');
            expect(target!.params.length).toBe(s.args.length);
            expect(m.visibility).toBe('public');
          }
          if (s.kind === 'add_raw_output' || s.kind === 'add_data_output') {
            expect(s.script.kind).toBe('var_ref');
            const name = (s.script as { name: string }).name;
            expect(m.params.find((p) => p.name === name)?.type).toBe('ByteString');
          }
        }
      }
    }
  });

  it('the default arbitraries still never draw them (fixed-seed corpora stay byte-stable)', () => {
    const defaults = [
      ...fc.sample(arbGeneratedContract, { numRuns: N, seed: SEED }),
      ...fc.sample(arbGeneratedStatefulContract, { numRuns: N, seed: SEED }),
    ];
    for (const c of defaults) {
      expect(
        has(c, 'add_raw_output') || has(c, 'add_data_output') || has(c, 'method_call') || has(c, 'raw_script'),
      ).toBe(false);
      expect(c.parentClass).not.toBe('UnsafeSmartContract');
      expect(c.methods.every((m) => m.visibility === 'public')).toBe(true);
    }
  });
});

describe('N-400: all seven renderers spell the new statements', () => {
  const find = (kind: Stmt['kind']) => [...STATEFUL, ...STATELESS].find((c) => has(c, kind))!;
  const SPELLING: Record<string, Record<string, RegExp>> = {
    add_raw_output: {
      ts: /this\.addRawOutput\(\d+n, \w+\);/,
      go: /c\.AddRawOutput\(\d+, \w+\)/,
      rs: /self\.add_raw_output\(\d+, \w+\);/,
      py: /self\.add_raw_output\(\d+, \w+\)/,
      zig: /self\.addRawOutput\(\d+, \w+\);/,
      rb: /^\s+add_raw_output\(\d+, \w+\)$/m,
      java: /this\.addRawOutput\(\d+L, \w+\);/,
    },
    add_data_output: {
      ts: /this\.addDataOutput\(\d+n, \w+\);/,
      go: /c\.AddDataOutput\(\d+, \w+\)/,
      rs: /self\.add_data_output\(\d+, \w+\);/,
      py: /self\.add_data_output\(\d+, \w+\)/,
      zig: /self\.addDataOutput\(\d+, \w+\);/,
      rb: /^\s+add_data_output\(\d+, \w+\)$/m,
      java: /this\.addDataOutput\(\d+L, \w+\);/,
    },
    method_call: {
      ts: /this\.helper\d+\(/,
      go: /c\.helper\d+\(/,
      rs: /self\.helper\d+\(/,
      py: /self\._helper\d+\(/,
      zig: /self\.helper\d+\(/,
      rb: /^\s+_helper\d+\(/m,
      java: /^\s+helper\d+\(/m,
    },
    raw_script: {
      ts: /asm\(\{ body: '[0-9a-f]+', in_arity: 0, out_arity: 1 \}\);/,
      go: /runar\.Asm\("[0-9a-f]+", 0, 1\)/,
      rs: /^\s+asm\("[0-9a-f]+", 0, 1\);/m,
      py: /^\s+asm\("[0-9a-f]+", 0, 1\)/m,
      zig: /runar\.asm\("[0-9a-f]+", 0, 1\);/,
      rb: /^\s+asm\("[0-9a-f]+", 0, 1\)$/m,
      java: /^\s+asm\("[0-9a-f]+", 0, 1\);/m,
    },
  };
  for (const kind of Object.keys(SPELLING)) {
    for (const fmt of Object.keys(SPELLING[kind]!)) {
      it(`${kind} renders in ${FORMAT_EXTENSIONS[fmt as keyof typeof FORMAT_EXTENSIONS]}`, () => {
        const src = RENDERERS[fmt as keyof typeof RENDERERS](find(kind as Stmt['kind']));
        expect(src).toMatch(SPELLING[kind]![fmt]!);
      });
    }
  }

  it('a private helper is declared private in each surface', () => {
    const c = STATEFUL.find((x) => has(x, 'method_call'))!;
    expect(RENDERERS.ts(c)).toMatch(/private helper\d+\(/);
    expect(RENDERERS.rs(c)).toMatch(/\n    fn helper\d+\(/);
    expect(RENDERERS.py(c)).toMatch(/def _helper\d+\(/);
    expect(RENDERERS.py(c)).not.toMatch(/@public\s*\n\s*def _helper/);
    expect(RENDERERS.zig(c)).toMatch(/\n    fn helper\d+\(/);
    expect(RENDERERS.go(c)).toMatch(/\) helper\d+\(/);
    expect(RENDERERS.rb(c)).toMatch(/private\n\s+params[^\n]*\n\s+def _helper\d+/);
    expect(RENDERERS.java(c)).not.toMatch(/@Public\s*\n\s*void helper/);
  });
});

describe('N-400: the TS compiler accepts every generated program (fold-OFF)', () => {
  it('compiles all sampled stateful and stateless programs', () => {
    for (const c of [...STATEFUL, ...STATELESS]) {
      const r = compile(RENDERERS.ts(c), { fileName: `${c.name}.runar.ts`, disableConstantFolding: true });
      const errors = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
      expect(errors, `${c.name}:\n${RENDERERS.ts(c)}`).toEqual([]);
      expect(r.scriptHex).toMatch(/^[0-9a-f]+$/);
    }
  }, 120_000);

  it('the new statements change the emitted bytes (the kinds are load-bearing)', () => {
    const c = STATEFUL.find((x) => has(x, 'add_data_output'))!;
    const strip = (stmts: Stmt[]): Stmt[] => stmts.filter((s) => s.kind !== 'add_data_output');
    const without: GeneratedContract = { ...c, methods: c.methods.map((m) => ({ ...m, body: strip(m.body) })) };
    const opts = { disableConstantFolding: true } as const;
    const a = compile(RENDERERS.ts(c), { fileName: 'A.runar.ts', ...opts });
    const b = compile(RENDERERS.ts(without), { fileName: 'B.runar.ts', ...opts });
    expect(a.scriptHex).not.toBe(b.scriptHex);
  });
});
