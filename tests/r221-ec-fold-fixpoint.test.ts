/**
 * R-221 (CL-GAP-073): the EC constant folder behaves differently across tiers.
 *
 * The finding says Rust and Zig "stop folding EC constants above a tier-local
 * magnitude (Rust above 2^53 because constants are stored as `"...n"` strings;
 * Zig above i128)". Measured, that is not the shape of it.
 *
 *  * Zig agrees with the majority at every magnitude tried, including a scalar
 *    just under the curve order. N-034 replaced its `u256` arithmetic with
 *    `const_arith.Big`, so that half of the finding was already closed.
 *
 *  * Rust folded correctly at 2^96 too. What it did NOT do is iterate. Go's
 *    `OptimizeEC` runs `for changed { ... }`, Python's `_optimize_method` runs
 *    `while changed:`, and Ruby, Zig and Java do the same, because one rule's
 *    output routinely enables another's. Rust applied the rules in a single
 *    pass and stopped one rewrite short whenever that happened.
 *
 * The contract below is the shape that exposes it. Rule 10 folds
 * `ecAdd(ecMulGen(k1), ecMulGen(k2))` to `ecMulGen(k1 + k2 mod N)`; with
 * k1 = N-7 and k2 = 7 the sum is 0, and Rule 5 then folds `ecMulGen(0)` to the
 * infinity-point constant. That second step needs a second pass. Measured
 * before the fix, fold-ON — the shipped default:
 *
 *     go python ruby java zig   1699920 hexchars   sha a609b3e20c
 *     rust                      2548922 hexchars   sha f1ca9484f1
 *
 * Rust emitted an extra 256-step ladder: a script ~425 KB larger than every
 * peer's, for the same source. That is a cross-tier byte divergence in the
 * default mode, which is what the fold-ON parity gate exists to prevent — no
 * conformance fixture happened to carry a scalar pair summing to 0 mod N.
 *
 * The magnitude control is the second case: at 2^96 every tier already agreed,
 * so a test that only compared big scalars would have passed while Rust was
 * still one pass short.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  findGoBinary,
  findRustBinary,
  findPythonBinary,
  findZigBinary,
  findRubyBinary,
  findJavaBinary,
} from '../conformance/runner/runner.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** secp256k1 group order. */
const N = 115792089237316195423570985008687907852837564279074904382605163141518161494337n;

function source(k1: bigint, k2: bigint): string {
  return `import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';

class ECFoldChain extends SmartContract {
  constructor() {
    super();
  }

  public spend(a: bigint, b: bigint) {
    assert(ecOnCurve(ecAdd(ecMulGen(${k1}n), ecMulGen(${k2}n))));
  }
}
`;
}

function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

interface Tier { id: string; binary: string | null; cwd: string }

const TIERS: Tier[] = [
  { id: 'go', binary: findGoBinary(), cwd: join(ROOT, 'compilers/go') },
  { id: 'rust', binary: findRustBinary(), cwd: join(ROOT, 'compilers/rust') },
  { id: 'python', binary: findPythonBinary(), cwd: join(ROOT, 'compilers/python') },
  { id: 'ruby', binary: findRubyBinary(), cwd: join(ROOT, 'compilers/ruby') },
  { id: 'java', binary: findJavaBinary(), cwd: join(ROOT, 'compilers/java') },
  { id: 'zig', binary: findZigBinary(), cwd: join(ROOT, 'compilers/zig') },
];

const available = TIERS.filter((t) => t.binary !== null && existsSync(t.cwd));

/** fold-ON (the shipped default): no --disable-constant-folding. */
function hexOf(tier: Tier, src: string): string {
  const { cmd, args } = splitCmd(tier.binary);
  const dir = mkdtempSync(join(tmpdir(), `r221-${tier.id}-`));
  try {
    const file = join(dir, 'ECFoldChain.runar.ts');
    writeFileSync(file, src);
    const res = spawnSync(cmd!, [...args, '--source', file, '--hex'], {
      cwd: tier.cwd,
      encoding: 'utf-8',
      timeout: 300_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    if (res.status !== 0) {
      throw new Error(`${tier.id} exited ${res.status}: ${(res.stderr || '').slice(0, 400)}`);
    }
    const first = (res.stdout.split('\n')[0] ?? '').replace(/\s/g, '').toLowerCase();
    if (!/^[0-9a-f]+$/.test(first)) {
      throw new Error(`${tier.id} printed no hex: ${res.stdout.slice(0, 200)}`);
    }
    return first;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function groupByHex(src: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const tier of available) {
    const hex = hexOf(tier, src);
    const ids = out.get(hex) ?? [];
    ids.push(tier.id);
    out.set(hex, ids);
  }
  return out;
}

describe('R-221: every tier folds an EC constant chain to the same fixpoint', () => {
  it('at least two tiers are built (a one-tier run proves nothing)', () => {
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('control: a chain that needs ONE pass already agreed everywhere', () => {
    // 2^96-ish scalars whose sum is not 0 mod N: Rule 10 fires, nothing
    // downstream of it does. This passed before the fix too, which is why it
    // is here — it isolates "iterates" from "handles big numbers".
    const groups = groupByHex(source(123456789012345678901234567890n, 7n));
    expect([...groups.values()].map((ids) => ids.join('+'))).toEqual([
      available.map((t) => t.id).join('+'),
    ]);
  }, 600_000);

  it('a chain that needs TWO passes agrees everywhere too', () => {
    // (N-7) + 7 === 0 mod N, so Rule 10's output enables Rule 5.
    const groups = groupByHex(source(N - 7n, 7n));
    expect(
      [...groups.values()].map((ids) => ids.join('+')),
      'a tier stopped one rewrite short of the others',
    ).toEqual([available.map((t) => t.id).join('+')]);
  }, 600_000);

  it('and the second pass really fired — the chain folded to a constant', () => {
    // Without the second pass the script carries an extra ecMulGen ladder. Pin
    // the size relation rather than an absolute, so ordinary codegen drift does
    // not rewrite this test.
    const oneStep = hexOf(available[0]!, source(123456789012345678901234567890n, 7n));
    const twoStep = hexOf(available[0]!, source(N - 7n, 7n));
    expect(
      twoStep.length,
      'the k1+k2 === 0 chain did not fold away its ladder',
    ).toBeLessThan(oneStep.length);
  }, 600_000);
});
