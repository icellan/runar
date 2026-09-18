/**
 * R-034 / CL-BUG-028 — `optimizer/ec-rules.json` is an UNENFORCED spec.
 *
 * The Go tier's EC optimizer is data-driven: `compilers/go/frontend/ec_rules_engine.go`
 * parses the JSON and executes whatever it finds. The other six tiers hand-port
 * every rule into procedural code (`optimizer/anf-ec.ts`,
 * `compilers/rust/src/frontend/anf_optimize.rs`,
 * `compilers/python/runar_compiler/frontend/anf_optimize.py`,
 * `compilers/zig/src/passes/ec_optimizer.zig`,
 * `compilers/ruby/lib/runar_compiler/frontend/anf_optimize.rb`,
 * `compilers/java/.../passes/AnfOptimize.java`).
 *
 * Nothing checked that the hand-ports were COMPLETE. They were not:
 * `ec-add-negate-cancel-reversed` sat in the JSON — and therefore in the Go
 * engine — with no counterpart in any of the six. Six tiers silently declined a
 * rewrite the seventh performed, which conformance invariant 2 (byte-identical
 * hex across tiers) forbids. One missing rule is a bug; a spec nobody validates
 * against its readers is the bug CLASS.
 *
 * This file is the gate for the class, at the layer that can be gated cheaply
 * and in-process: every rule named in `ec-rules.json` must have a probe here,
 * and every probe must actually fire in the TS optimizer. Add a rule to the
 * JSON without porting it to TS and `covers every rule` goes red.
 *
 * WHAT THIS GATE DOES NOT DO — stated plainly, because an overclaimed gate is
 * how the original defect survived. It gates ONE reader (TS). The five
 * remaining hand-ported tiers have no equivalent completeness check; the
 * durable fix for them is a conformance fixture per rule driven through
 * `runner/index.ts --ir-parity`, which is the serialized conformance surface.
 * `r034-ec-negate-cancel-parity.test.ts` does that cross-tier check for the two
 * negate-cancel rules only.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { optimizeEC } from '../optimizer/anf-ec.js';
import type { ANFProgram, ANFBinding, ANFValue } from '../ir/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..', '..');
const CANONICAL_RULES = join(REPO_ROOT, 'optimizer', 'ec-rules.json');
const GO_EMBEDDED_RULES = join(REPO_ROOT, 'compilers', 'go', 'frontend', 'ec-rules.json');

// ---------------------------------------------------------------------------
// Constants (mirrors of the ones in optimizer/anf-ec.ts)
// ---------------------------------------------------------------------------

const INFINITY_HEX = '0'.repeat(128);
const GEN_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GEN_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const G_HEX = GEN_X.toString(16).padStart(64, '0') + GEN_Y.toString(16).padStart(64, '0');

// ---------------------------------------------------------------------------
// Probe harness
// ---------------------------------------------------------------------------

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

function program(body: ANFBinding[]): ANFProgram {
  return {
    contractName: 'ECRules',
    properties: [],
    methods: [{ name: 'm', params: [], body, isPublic: true }],
  };
}

function findBinding(p: ANFProgram, name: string): ANFBinding | undefined {
  for (const method of p.methods) {
    for (const binding of method.body) if (binding.name === name) return binding;
  }
  return undefined;
}

/**
 * Normalised one-line description of what a binding holds after optimisation.
 * `ref:<name>` is the `@ref:` alias form the optimizer uses for "replace with
 * the value that was already bound to <name>".
 */
function describeValue(p: ANFProgram, name: string): string {
  const binding = findBinding(p, name);
  if (!binding) return 'MISSING';
  const v = binding.value;
  if (v.kind === 'load_const') {
    if (typeof v.value === 'string') {
      if (v.value === INFINITY_HEX) return 'const:INFINITY';
      if (v.value === G_HEX) return 'const:G';
      if (v.value.startsWith('@ref:')) return `ref:${v.value.slice(5)}`;
      return `const:str`;
    }
    return `const:${String(v.value)}`;
  }
  if (v.kind === 'call') return `call:${v.func}`;
  return v.kind;
}

/** Scalar a rewritten call was handed, resolved through the fresh const binding. */
function scalarOf(p: ANFProgram, name: string, argIndex: number): bigint | undefined {
  const binding = findBinding(p, name);
  if (!binding || binding.value.kind !== 'call') return undefined;
  const argName = binding.value.args[argIndex];
  if (argName === undefined) return undefined;
  const arg = findBinding(p, argName);
  if (!arg || arg.value.kind !== 'load_const' || typeof arg.value.value !== 'bigint') return undefined;
  return arg.value.value;
}

interface Probe {
  /** Bindings BEFORE optimisation; `target` is the binding the rule rewrites. */
  body: ANFBinding[];
  target: string;
  /** `describeValue` of the target AFTER optimisation when the rule fires. */
  fired: string;
  /** `describeValue` of the target when the rule does NOT fire — the RED shape. */
  declined: string;
  /** Optional extra assertion (scalar folding). */
  check?: (p: ANFProgram) => void;
}

const P = b('p', { kind: 'load_param', name: 'pt' });
const K = b('k', { kind: 'load_param', name: 'k' });
const INF = b('inf', { kind: 'load_const', value: INFINITY_HEX });
const GEN = b('g', { kind: 'load_const', value: G_HEX });
const ZERO = b('zero', { kind: 'load_const', value: 0n });
const ONE = b('one', { kind: 'load_const', value: 1n });
const FIVE = b('five', { kind: 'load_const', value: 5n });
const SEVEN = b('seven', { kind: 'load_const', value: 7n });

/**
 * One probe per rule in `optimizer/ec-rules.json`, keyed by the rule's
 * canonical name. Operands are spelled so the pattern variable that appears
 * twice ($x, $p) binds to the SAME ANF binding name — no tier's matcher
 * resolves through `@ref:` aliases or through two distinct `load_param`
 * bindings of the same parameter, so any other spelling would make every probe
 * decline and prove nothing.
 */
const PROBES: Record<string, Probe> = {
  'ec-add-identity-right': {
    body: [P, INF, b('t', { kind: 'call', func: 'ecAdd', args: ['p', 'inf'] }), b('a', { kind: 'assert', value: 't' })],
    target: 't', fired: 'ref:p', declined: 'call:ecAdd',
  },
  'ec-add-identity-left': {
    body: [P, INF, b('t', { kind: 'call', func: 'ecAdd', args: ['inf', 'p'] }), b('a', { kind: 'assert', value: 't' })],
    target: 't', fired: 'ref:p', declined: 'call:ecAdd',
  },
  'ec-mul-one': {
    body: [P, ONE, b('t', { kind: 'call', func: 'ecMul', args: ['p', 'one'] }), b('a', { kind: 'assert', value: 't' })],
    target: 't', fired: 'ref:p', declined: 'call:ecMul',
  },
  'ec-mul-zero': {
    body: [P, ZERO, b('t', { kind: 'call', func: 'ecMul', args: ['p', 'zero'] }), b('a', { kind: 'assert', value: 't' })],
    target: 't', fired: 'const:INFINITY', declined: 'call:ecMul',
  },
  'ec-mulgen-zero': {
    body: [ZERO, b('t', { kind: 'call', func: 'ecMulGen', args: ['zero'] }), b('a', { kind: 'assert', value: 't' })],
    target: 't', fired: 'const:INFINITY', declined: 'call:ecMulGen',
  },
  'ec-mulgen-one': {
    body: [ONE, b('t', { kind: 'call', func: 'ecMulGen', args: ['one'] }), b('a', { kind: 'assert', value: 't' })],
    target: 't', fired: 'const:G', declined: 'call:ecMulGen',
  },
  'ec-negate-negate': {
    body: [
      P,
      b('n1', { kind: 'call', func: 'ecNegate', args: ['p'] }),
      b('t', { kind: 'call', func: 'ecNegate', args: ['n1'] }),
      b('a', { kind: 'assert', value: 't' }),
    ],
    target: 't', fired: 'ref:p', declined: 'call:ecNegate',
  },
  'ec-add-negate-cancel': {
    body: [
      P,
      b('n', { kind: 'call', func: 'ecNegate', args: ['p'] }),
      b('t', { kind: 'call', func: 'ecAdd', args: ['p', 'n'] }),
      b('a', { kind: 'assert', value: 't' }),
    ],
    target: 't', fired: 'const:INFINITY', declined: 'call:ecAdd',
  },
  'ec-add-negate-cancel-reversed': {
    body: [
      P,
      b('n', { kind: 'call', func: 'ecNegate', args: ['p'] }),
      b('t', { kind: 'call', func: 'ecAdd', args: ['n', 'p'] }),
      b('a', { kind: 'assert', value: 't' }),
    ],
    target: 't', fired: 'const:INFINITY', declined: 'call:ecAdd',
  },
  'ec-mul-associative': {
    body: [
      P, FIVE, SEVEN,
      b('m1', { kind: 'call', func: 'ecMul', args: ['p', 'five'] }),
      b('t', { kind: 'call', func: 'ecMul', args: ['m1', 'seven'] }),
      b('a', { kind: 'assert', value: 't' }),
    ],
    target: 't', fired: 'call:ecMul', declined: 'call:ecMul',
    check: (p) => expect(scalarOf(p, 't', 1)).toBe(35n),
  },
  'ec-mulgen-linear': {
    body: [
      FIVE, SEVEN,
      b('g1', { kind: 'call', func: 'ecMulGen', args: ['five'] }),
      b('g2', { kind: 'call', func: 'ecMulGen', args: ['seven'] }),
      b('t', { kind: 'call', func: 'ecAdd', args: ['g1', 'g2'] }),
      b('a', { kind: 'assert', value: 't' }),
    ],
    target: 't', fired: 'call:ecMulGen', declined: 'call:ecAdd',
    check: (p) => expect(scalarOf(p, 't', 0)).toBe(12n),
  },
  'ec-mul-distributive': {
    body: [
      P, FIVE, SEVEN,
      b('m1', { kind: 'call', func: 'ecMul', args: ['p', 'five'] }),
      b('m2', { kind: 'call', func: 'ecMul', args: ['p', 'seven'] }),
      b('t', { kind: 'call', func: 'ecAdd', args: ['m1', 'm2'] }),
      b('a', { kind: 'assert', value: 't' }),
    ],
    target: 't', fired: 'call:ecMul', declined: 'call:ecAdd',
    check: (p) => expect(scalarOf(p, 't', 1)).toBe(12n),
  },
  'ec-mul-generator-specialize': {
    body: [GEN, K, b('t', { kind: 'call', func: 'ecMul', args: ['g', 'k'] }), b('a', { kind: 'assert', value: 't' })],
    target: 't', fired: 'call:ecMulGen', declined: 'call:ecMul',
  },
};

/**
 * The completeness check itself, as a pure function so the gate's own
 * self-test can drive it with a doctored rule list. Returns the rule names
 * that the JSON declares and this file does not probe.
 */
export function unprobedRules(ruleNames: readonly string[], probeNames: readonly string[]): string[] {
  const probed = new Set(probeNames);
  return ruleNames.filter((n) => !probed.has(n));
}

function ruleNamesFromJson(path: string): string[] {
  const rules = JSON.parse(readFileSync(path, 'utf-8')) as Array<{ name: string }>;
  return rules.map((r) => r.name);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ec-rules.json is a spec its readers are checked against', () => {
  it('the two checked-in copies are byte-identical', () => {
    const canonical = readFileSync(CANONICAL_RULES);
    const embedded = readFileSync(GO_EMBEDDED_RULES);
    // Byte comparison, not a parsed-value comparison: the Go engine `go:embed`s
    // its copy verbatim, so a whitespace-only drift is still two specs.
    expect(embedded.equals(canonical)).toBe(true);
  });

  it('covers every rule: each name in ec-rules.json has a probe here', () => {
    const missing = unprobedRules(ruleNamesFromJson(CANONICAL_RULES), Object.keys(PROBES));
    expect(missing).toEqual([]);
  });

  it('probes no rule the spec does not declare', () => {
    const declared = new Set(ruleNamesFromJson(CANONICAL_RULES));
    expect(Object.keys(PROBES).filter((n) => !declared.has(n))).toEqual([]);
  });

  // The gate's own failure mode. `unprobedRules` is what turns "the JSON grew"
  // into a red test; a gate that cannot go red is decoration.
  it('SELF-TEST: the gate reports a rule the readers have not ported', () => {
    const withNewRule = [...ruleNamesFromJson(CANONICAL_RULES), 'ec-hypothetical-new-rule'];
    expect(unprobedRules(withNewRule, Object.keys(PROBES))).toEqual(['ec-hypothetical-new-rule']);
    // ...and stays green while the spec and the readers agree.
    expect(unprobedRules(withNewRule, [...Object.keys(PROBES), 'ec-hypothetical-new-rule'])).toEqual([]);
  });
});

describe('every ec-rules.json rule actually fires in the TS optimizer', () => {
  for (const [name, probe] of Object.entries(PROBES)) {
    it(`${name} rewrites its probe`, () => {
      const optimized = optimizeEC(program(probe.body));
      const actual = describeValue(optimized, probe.target);
      // Report the declined shape explicitly — "expected const:INFINITY, got
      // call:ecAdd" is the whole diagnosis for an unported rule.
      expect(
        actual,
        actual === probe.declined
          ? `${name}: the rewrite DECLINED (target still ${probe.declined}) — this tier has not ported the rule`
          : `${name}: unexpected optimizer output`,
      ).toBe(probe.fired);
      probe.check?.(optimized);
    });
  }
});
