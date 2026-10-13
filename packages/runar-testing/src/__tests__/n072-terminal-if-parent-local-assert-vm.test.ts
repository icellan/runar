/**
 * N-072 — every tier: a TERMINAL `if` whose arm asserts a local declared
 * BEFORE the `if` dropped that arm's verdict and pushed an empty placeholder in
 * its place, so a spend the source accepts was rejected on-chain:
 *
 *     public go(a: boolean, b: boolean, c: boolean) {
 *       const x = a;
 *       if (c) { assert(x); } else { assert(b); }   // go(true, *, true) must pass
 *     }
 *
 * Mechanism (05-stack-lower `lowerIf`): under a terminal assert each arm leaves
 * exactly one slot, its verdict, and NIPs everything beneath it. The then-arm's
 * verdict slot still carried the parent name `x`, while the else-arm had NIPped
 * `x` away. The phase-1 consumption balance read that as "else consumed x,
 * then did not" and emitted a matching DROP of `x` in the then-arm — which was
 * the verdict itself — and phase 3 padded the depth back with OP_0. The emitted
 * then-arm was `NIP DROP OP_0`: it leaves 0 whatever `x` is. All seven tiers
 * shipped the same bytes (Go refused most shapes with an internal codegen error
 * instead, and miscompiled `T-local-both`).
 *
 * The acceptance oracle is `@bsv/sdk`'s `Spend` under the consensus spend
 * context, fed each tier's own emitted hex. Every expected verdict is derived
 * by hand from the source, never from compiler output.
 *
 * What this proves: for each shape below, each of the seven tiers emits a
 * script whose Spend verdict equals the source's for all eight (a, b, c)
 * witnesses, in both constant-folding modes, and all seven emit the same bytes.
 * The controls (`T-local-same`, `T-both-params`) pin that the two shapes which
 * already compiled correctly keep their exact bytes, and the non-uniform
 * terminal `if` (N-071's shape) stays refused at the source.
 * What it does NOT prove: terminal `if`s whose arms REBIND a pre-`if` local
 * (`let k = 0n; if (c) { k = 1n; assert(a); } else { …; assert(b); }`) — those
 * are refused today by the branch-result layout check, a separate defect — or
 * hostile `--ir` input beyond what the N-071 terminal-assert rule refuses.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import { newConsensusSpend, CONSENSUS_SPEND_CONTEXT } from '../consensus-spend.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n072-'));
const FILE = 'Probe.runar.ts';

function source(body: string): string {
  return `import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  constructor() { super(); }

  public go(a: boolean, b: boolean, c: boolean): void {
    ${body}
  }
}
`;
}

interface Shape {
  name: string;
  body: string;
  expect: (a: boolean, b: boolean, c: boolean) => boolean;
  /** Bytes that must not move (shapes that already compiled correctly). */
  pinnedHex?: string;
}

const SHAPES: Shape[] = [
  { name: 'T-local-then', body: `const x = a; if (c) { assert(x); } else { assert(b); }`, expect: (a, b, c) => (c ? a : b) },
  { name: 'T-local-else', body: `const y = b; if (c) { assert(a); } else { assert(y); }`, expect: (a, b, c) => (c ? a : b) },
  { name: 'T-local-both', body: `const x = a; const y = b; if (c) { assert(x); } else { assert(y); }`, expect: (a, b, c) => (c ? a : b) },
  { name: 'T-local-nested', body: `const x = a; if (c) { if (b) { assert(x); } else { assert(b); } } else { assert(b); }`, expect: (a, b, c) => (c ? (b ? a : false) : b) },
  { name: 'T-local-twoassert', body: `const x = a; if (c) { assert(b); assert(x); } else { assert(b); }`, expect: (a, b, c) => (c ? a && b : b) },
  // Controls: compiled and spent correctly before the fix; bytes pinned.
  {
    name: 'T-local-same', body: `const x = a; if (c) { assert(x); } else { assert(x); }`, expect: (a) => a,
    pinnedHex: '52797600877c51879b69787600877c51879b69767600877c51879b697b7c6377677768',
  },
  {
    name: 'T-both-params', body: `if (c) { assert(a); } else { assert(b); }`, expect: (a, b, c) => (c ? a : b),
    pinnedHex: '52797600877c51879b69787600877c51879b69767600877c51879b69637c77677768',
  },
];

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `gradle jar` in compilers/java');
  return join(libs, jar);
}

function run(cmd: string, args: string[], cwd?: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 32 * 1024 * 1024 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}: ${r.stderr}`);
  return r.stdout.trim().split('\n').pop()!.trim();
}

let seq = 0;
function writeTmp(src: string): string {
  const dir = join(TMP, String(seq++));
  mkdirSync(dir);
  const p = join(dir, FILE);
  writeFileSync(p, src);
  return p;
}

type Tier = { name: string; hex: (src: string, fold: boolean) => string };
const foldFlag = (fold: boolean): string[] => (fold ? [] : ['--disable-constant-folding']);

const TIERS: Tier[] = [
  {
    name: 'ts',
    hex: (src, fold) => {
      const r = compile(src, { fileName: FILE, disableConstantFolding: !fold });
      if (!r.success || !r.scriptHex) {
        throw new Error(r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join('\n'));
      }
      return r.scriptHex;
    },
  },
  {
    name: 'go',
    hex: (src, fold) => run(
      requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'),
      ['--source', writeTmp(src), '--hex', ...foldFlag(fold)],
    ),
  },
  {
    name: 'rust',
    hex: (src, fold) => run(
      requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'),
      ['--source', writeTmp(src), '--hex', ...foldFlag(fold)],
    ),
  },
  {
    name: 'python',
    hex: (src, fold) => run('python3', ['-m', 'runar_compiler', '--source', writeTmp(src), '--hex', ...foldFlag(fold)], join(REPO, 'compilers', 'python')),
  },
  {
    name: 'zig',
    hex: (src, fold) => run(
      requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build -Doptimize=ReleaseSafe'),
      ['--source', writeTmp(src), '--hex', ...foldFlag(fold)],
    ),
  },
  {
    name: 'ruby',
    hex: (src, fold) => run('ruby', [
      '-I', join(REPO, 'compilers', 'ruby', 'lib'),
      join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby'),
      '--source', writeTmp(src), '--hex', ...foldFlag(fold),
    ]),
  },
  {
    name: 'java',
    hex: (src, fold) => run('java', ['-jar', javaJar(), '--source', writeTmp(src), '--hex', ...foldFlag(fold)]),
  },
];

/** Spend `go(a, b, c)` against `lockingHex`; the witness pushes a, b, c in ABI order. */
function spends(lockingHex: string, a: boolean, b: boolean, c: boolean): boolean {
  const push = (v: boolean): string => (v ? '51' : '00');
  const spend = newConsensusSpend({
    ...CONSENSUS_SPEND_CONTEXT,
    lockingScript: LockingScript.fromHex(lockingHex),
    unlockingScript: UnlockingScript.fromHex(push(a) + push(b) + push(c)),
    otherInputs: [],
    outputs: [],
  });
  try {
    return spend.validate();
  } catch {
    return false;
  }
}

const BOOLS = [false, true];

for (const fold of [false, true]) {
  for (const shape of SHAPES) {
    describe(`N-072 [${shape.name}, fold ${fold ? 'on' : 'off'}] — terminal if arm keeps its own verdict`, () => {
      const src = source(shape.body);
      const hexes = new Map<string, string | Error>();
      for (const t of TIERS) {
        try {
          hexes.set(t.name, t.hex(src, fold));
        } catch (e) {
          hexes.set(t.name, e instanceof Error ? e : new Error(String(e)));
        }
      }

      for (const [tier, hex] of hexes) {
        it(`[${tier}] compiles, and Spend agrees with the source on all 8 witnesses`, () => {
          if (hex instanceof Error) throw hex;
          const wrong: string[] = [];
          for (const a of BOOLS) for (const b of BOOLS) for (const c of BOOLS) {
            const want = shape.expect(a, b, c);
            if (spends(hex, a, b, c) !== want) wrong.push(`go(${a}, ${b}, ${c}) should ${want ? 'pass' : 'fail'}`);
          }
          expect(wrong, `script ${hex}`).toEqual([]);
        });
      }

      it('all seven tiers emit the same bytes', () => {
        const ts = hexes.get('ts');
        for (const [tier, hex] of hexes) expect(hex, `${tier} diverges from ts`).toEqual(ts);
        if (shape.pinnedHex) expect(ts).toBe(shape.pinnedHex);
      });
    });
  }
}

describe('N-072 — the non-uniform terminal if (N-071) stays refused at the source', () => {
  it('ts refuses an else-arm that does not end with an assert', () => {
    const r = compile(source(`if (c) { assert(a); } else { const z = b; }`), { fileName: FILE });
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toContain('must end with an assert() call');
  });
});
