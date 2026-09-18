/**
 * ec-mulgen-linear: cross-tier hex parity for the RUNTIME-scalar shape.
 *
 * `optimizer/ec-rules.json` defines
 *
 *     ecAdd(ecMulGen($k1), ecMulGen($k2))  ->  ecMulGen($k1 + $k2)
 *
 * with no "supported" tag, i.e. every tier is expected to implement it and
 * every tier is expected to implement it the SAME way. Six tiers (TS, Rust,
 * Python, Zig, Ruby, Java) fire it only when BOTH scalars resolve to
 * compile-time constants, folding the sum mod n at rewrite time. The Go rule
 * engine used to fire it unconditionally, synthesising a runtime `bin_op "+"`
 * helper for non-constant scalars — so the same source compiled to a
 * different script depending on which tier compiled it, which is exactly what
 * conformance invariant 2 (byte-identical hex across tiers) forbids.
 *
 * This test pins both halves:
 *   - runtime scalars: the rewrite must NOT fire anywhere, so TS and Go agree
 *   - constant scalars (control): the rewrite fires in both, and did before
 *
 * The Go compiler is driven through `--ir`, i.e. it re-runs its own EC
 * optimizer over the ANF the TS tier already optimized. That is the harness
 * that made the divergence observable: a rule that fires in Go but not in TS
 * rewrites the TS-optimized ANF a second time.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync } from 'child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { compile } from '../index.js';
import type { ANFProgram } from '../ir/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const GO_COMPILER_DIR = join(__dirname, '..', '..', '..', '..', 'compilers', 'go');

let hasGo = false;
try {
  execSync('go version', { stdio: 'pipe' });
  hasGo = true;
} catch {
  // Go toolchain not installed — the suite skips rather than fails locally.
}

/**
 * Inline spelling on purpose: binding the operands to `const p = ...` first
 * makes ANF lowering insert `@ref:` alias bindings between the ecAdd and the
 * ecMulGen calls, and no tier's matcher resolves through those, so the rule
 * cannot fire either way and the test would prove nothing.
 */
function contractSource(k1: string, k2: string): string {
  return `
import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';

class ECLinear extends SmartContract {
    constructor() {
        super();
    }

    public spend(a: bigint, b: bigint) {
        assert(ecOnCurve(ecAdd(ecMulGen(${k1}), ecMulGen(${k2}))));
    }
}
`;
}

/** Same bigint encoding the cross-compiler suite uses for the Go IR decoder. */
function anfToJson(anf: ANFProgram): string {
  return JSON.stringify(anf, (_key, value) => {
    if (typeof value === 'bigint') {
      if (value >= Number.MIN_SAFE_INTEGER && value <= Number.MAX_SAFE_INTEGER) {
        return Number(value);
      }
      return value.toString() + 'n';
    }
    return value;
  }, 2);
}

function runGoCompiler(irFilePath: string): string {
  const result = execSync(
    `go run . --ir "${irFilePath}" --hex --disable-constant-folding`,
    {
      cwd: GO_COMPILER_DIR,
      timeout: 120000,
      stdio: ['pipe', 'pipe', 'pipe'],
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  return result.toString().trim();
}

describe.skipIf(!hasGo)('ec-mulgen-linear: TS/Go hex parity', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-ec-mulgen-linear-'));
  });

  afterAll(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  function tsAndGoHex(tag: string, k1: string, k2: string): { ts: string; go: string } {
    const result = compile(contractSource(k1, k2), { disableConstantFolding: true });
    if (!result.success) {
      const errors = result.diagnostics.filter(d => d.severity === 'error');
      throw new Error(`TS compile failed:\n` + errors.map(e => `  ${e.message}`).join('\n'));
    }
    expect(result.anf).not.toBeNull();
    const irPath = join(tempDir, `${tag}.anf.json`);
    writeFileSync(irPath, anfToJson(result.anf!));
    return {
      ts: (result.scriptHex as string).toLowerCase(),
      go: runGoCompiler(irPath).toLowerCase(),
    };
  }

  /**
   * Compares without handing vitest two ~1 MB strings to diff — a mismatch
   * here would otherwise print megabytes of hex.
   */
  function expectSameHex(ts: string, go: string): void {
    if (ts === go) return;
    let i = 0;
    while (i < ts.length && i < go.length && ts[i] === go[i]) i++;
    throw new Error(
      `Go and TS hex differ: tsLen=${ts.length} goLen=${go.length} firstDiffAt=${i}\n` +
      `  ts: …${ts.slice(Math.max(0, i - 16), i + 16)}…\n` +
      `  go: …${go.slice(Math.max(0, i - 16), i + 16)}…`,
    );
  }

  it('runtime scalars: TS and Go produce byte-identical hex', () => {
    const { ts, go } = tsAndGoHex('runtime', 'a', 'b');
    expectSameHex(ts, go);
  });

  it('runtime scalars: the rewrite does not fire, so the ecAdd survives', () => {
    const result = compile(contractSource('a', 'b'), { disableConstantFolding: true });
    expect(result.success).toBe(true);
    const spend = result.anf!.methods.find(m => m.name === 'spend');
    expect(spend).toBeDefined();
    const calls = spend!.body
      .filter(b => b.value.kind === 'call')
      .map(b => (b.value as { func: string }).func);
    expect(calls).toContain('ecAdd');
    // Two generator multiplications in, two out — no synthesized third one.
    expect(calls.filter(f => f === 'ecMulGen')).toHaveLength(2);
  });

  it('control — constant scalars: TS and Go produce byte-identical hex', () => {
    const { ts, go } = tsAndGoHex('const', '5n', '7n');
    expectSameHex(ts, go);
  });

  it('control — constant scalars: the rewrite still folds 5 + 7 to 12', () => {
    const result = compile(contractSource('5n', '7n'), { disableConstantFolding: true });
    expect(result.success).toBe(true);
    const spend = result.anf!.methods.find(m => m.name === 'spend')!;
    const ecAdds = spend.body.filter(
      b => b.value.kind === 'call' && (b.value as { func: string }).func === 'ecAdd',
    );
    expect(ecAdds).toHaveLength(0);
    const folded = spend.body.find(
      b => b.value.kind === 'load_const' && (b.value as { value: unknown }).value === 12n,
    );
    expect(folded).toBeDefined();
  });
});
