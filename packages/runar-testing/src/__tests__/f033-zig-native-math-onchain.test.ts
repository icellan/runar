/**
 * F-033 (CL-BUG-104) — the on-chain half of the Zig native-runtime math check.
 *
 * `packages/runar-zig/src/builtins.zig` is the runtime every native
 * `.runar.zig` contract test links against. Its `percentOf` divided by 100
 * while the compiled script divides by 10000 (basis points), so a native test
 * and the deployed contract disagreed 100x on every fee. This file pins what
 * the COMPILED SCRIPT actually returns, on `@bsv/sdk` `Spend.validate`, for
 * every vector the Zig side replays natively:
 *
 *   - packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json
 *       one builtin call per case; Zig: builtins_math_onchain_test.zig
 *   - examples/zig/{math-demo,function-patterns}/onchain-vectors.json
 *       one real stateful method call per case, on the shipped .runar.zig
 *       example; Zig: MathDemo_test.zig / FunctionPatterns_test.zig
 *
 * Both sides read the same JSON, so native == JSON == on-chain.
 *
 * How a value is pinned: a probe method `assert(f(args) === e)` must ACCEPT
 * with e = expect and REJECT with e = expect + 1 (a script that accepts
 * everything cannot pass). An `abort` case must reject BOTH
 * `assert(f(args) === 0)` and `assert(f(args) !== 0)`: no value satisfies
 * either, so the script failed before the comparison.
 *
 * Example vectors run the real contract through `runStatefulSpend` (deploy ->
 * call, validated by `Spend.validate` against the real BIP-143 preimage) and
 * read the new `value` / `balance` from the accepted continuation output.
 *
 * What this does NOT prove: anything about the native Zig runtime by itself —
 * that is the Zig half. Values are limited to i64 because the Zig native
 * Bigint is i64; the script's arbitrary-precision range beyond that is not
 * exercised here.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ScriptExecutionContract } from '../script-execution.js';
import { runStatefulSpend, testKey } from '../oracle/index.js';

const REPO = resolve(__dirname, '../../../..');

type Expect = bigint | boolean | 'abort';

/** Parse JSON keeping every integer exact (2^63-1 does not survive a double). */
function readVectors<T>(rel: string): T {
  const text = readFileSync(resolve(REPO, rel), 'utf8');
  return JSON.parse(text, (_k, v, ctx?: { source?: string }) => {
    if (typeof v !== 'number') return v;
    if (!ctx || ctx.source === undefined) {
      throw new Error('JSON.parse reviver has no source text (needs Node >= 21)');
    }
    return BigInt(ctx.source);
  }) as T;
}

// ---------------------------------------------------------------------------
// Builtin vectors
// ---------------------------------------------------------------------------

interface BuiltinCase {
  fn: string;
  args: bigint[];
  expect: Expect;
}

const BOOL_FNS = new Set(['within', 'bool']);
const ARITY: Record<string, number> = {
  percentOf: 2, mulDiv: 3, safediv: 2, safemod: 2, divmod: 2, sqrt: 1, log2: 1,
  pow: 2, clamp: 3, within: 3, sign: 1, gcd: 2, abs: 1, min: 2, max: 2, bool: 1,
};

function probeSource(): string {
  const fns = Object.keys(ARITY);
  const methods = fns
    .map((fn) => {
      const n = ARITY[fn]!;
      const params = Array.from({ length: n }, (_, i) => `a${i}: bigint`).join(', ');
      const call = `${fn}(${Array.from({ length: n }, (_, i) => `a${i}`).join(', ')})`;
      const eType = BOOL_FNS.has(fn) ? 'boolean' : 'bigint';
      return [
        `  public eq_${fn}(${params}, e: ${eType}) { assert(${call} === e); }`,
        `  public ne_${fn}(${params}, e: ${eType}) { assert(${call} !== e); }`,
      ].join('\n');
    })
    .join('\n');
  return [
    `import { SmartContract, assert, ${fns.join(', ')} } from 'runar-lang';`,
    `class F033MathProbe extends SmartContract {`,
    `  constructor() { super(); }`,
    methods,
    `}`,
  ].join('\n');
}

describe('F-033: math builtins — compiled script verdict on Spend.validate', () => {
  const { cases } = readVectors<{ cases: BuiltinCase[] }>(
    'packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json',
  );
  const probe = ScriptExecutionContract.fromSource(probeSource(), {}, 'F033MathProbe.runar.ts');

  it('covers every builtin the Zig runtime exports', () => {
    expect(new Set(cases.map((c) => c.fn))).toEqual(new Set(Object.keys(ARITY)));
  });

  for (const c of cases) {
    const label = `${c.fn}(${c.args.join(', ')}) -> ${String(c.expect)}`;
    it(label, () => {
      const isBool = BOOL_FNS.has(c.fn);
      if (c.expect === 'abort') {
        const zero = isBool ? false : 0n;
        const eq = probe.execute(`eq_${c.fn}`, [...c.args, zero]);
        const ne = probe.execute(`ne_${c.fn}`, [...c.args, zero]);
        expect(eq.success, 'f(args) === 0 must not verify').toBe(false);
        expect(ne.success, 'f(args) !== 0 must not verify').toBe(false);
        return;
      }
      const ok = probe.execute(`eq_${c.fn}`, [...c.args, c.expect]);
      expect(ok.success, ok.error).toBe(true);
      const wrong = isBool ? !(c.expect as boolean) : (c.expect as bigint) + 1n;
      expect(probe.execute(`eq_${c.fn}`, [...c.args, wrong]).success).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// Example-contract vectors (the real .runar.zig sources, stateful spends)
// ---------------------------------------------------------------------------

interface ExampleCase {
  init: bigint;
  method: string;
  args: bigint[];
  expect: bigint | 'abort';
  /** The SDK cannot build this call at all (see the JSON `_doc`). */
  sdkRefuses?: boolean;
}

/**
 * An accepted spend must land on `expect`. An `abort` spend must be rejected
 * by the ENGINE (`reachedEngine`): a reject the SDK raised before the script
 * ran would say nothing about the script.
 */
function checkExampleVerdict(
  label: string,
  c: ExampleCase,
  r: Awaited<ReturnType<typeof runStatefulSpend>>,
  field: string,
): void {
  if (c.sdkRefuses) {
    // No spend exists to replay; pin the refusal reason so a different
    // failure cannot hide here. The engine verdict for the builtin itself is
    // the stateless `mulDiv(1, 1, 0)` abort vector above.
    expect(c.expect).toBe('abort');
    expect(r.vmAccepted).toBe(false);
    expect(r.vmError, label).toMatch(/Division by zero/);
    return;
  }
  if (c.expect === 'abort') {
    expect(r.vmAccepted, `${label}: must be rejected on-chain`).toBe(false);
    expect(r.reachedEngine, `${label}: rejected before the engine ran: ${r.vmError}`).toBe(true);
    return;
  }
  expect(r.vmAccepted, `${label}: ${r.vmError}`).toBe(true);
  expect(r.continuationState?.[field], label).toBe(c.expect);
}

describe('F-033: examples/zig math contracts — compiled script verdict on Spend.validate', () => {
  it('MathDemo.runar.zig: every vector matches the on-chain verdict', async () => {
    const rel = 'examples/zig/math-demo/MathDemo.runar.zig';
    const source = readFileSync(resolve(REPO, rel), 'utf8');
    const { cases } = readVectors<{ cases: ExampleCase[] }>('examples/zig/math-demo/onchain-vectors.json');
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      const r = await runStatefulSpend({
        source,
        fileName: 'MathDemo.runar.zig',
        method: c.method,
        args: c.args,
        constructorArgs: [c.init],
        signerKey: 'alice',
      });
      checkExampleVerdict(`MathDemo(${c.init}).${c.method}(${c.args.join(', ')})`, c, r, 'value');
    }
  }, 120_000);

  it('FunctionPatterns.runar.zig: every vector matches the on-chain verdict', async () => {
    const rel = 'examples/zig/function-patterns/FunctionPatterns.runar.zig';
    const source = readFileSync(resolve(REPO, rel), 'utf8');
    const { cases } = readVectors<{ cases: ExampleCase[] }>(
      'examples/zig/function-patterns/onchain-vectors.json',
    );
    expect(cases.length).toBeGreaterThan(0);
    const alice = testKey('alice');
    for (const c of cases) {
      const r = await runStatefulSpend({
        source,
        fileName: 'FunctionPatterns.runar.zig',
        method: c.method,
        // Sig param first: `null` makes the SDK sign input 0 with the signer.
        args: [null, ...c.args],
        constructorArgs: [alice.pubKey, c.init],
        signerKey: 'alice',
      });
      checkExampleVerdict(`FunctionPatterns(${c.init}).${c.method}(${c.args.join(', ')})`, c, r, 'balance');
    }
  }, 120_000);
});
