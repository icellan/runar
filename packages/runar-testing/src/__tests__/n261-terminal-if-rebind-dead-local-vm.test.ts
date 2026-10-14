/**
 * N-261 — every tier: a TERMINAL `if` whose arms rebind a local that nothing
 * reads afterwards was refused by all seven compilers, although the source is
 * legal:
 *
 *     public go(a: boolean, b: boolean, c: boolean) {
 *       let k = 0n;
 *       if (c) { k = 1n; assert(a); } else { k = 2n; assert(b); }
 *     }
 *
 * Mechanism (04-anf-lower `lowerIfStatement`): `k` is a branch-merged local, so
 * the `if` declared results [k] and `appendBranchResults` appended the
 * `__merge$` rebind block to each arm AFTER its assert. The arm then no longer
 * ended in an assert: Go's IR validator refused the method, and in the other
 * tiers 05-stack-lower's terminal-arm cleanup left the verdict (named
 * anonymously since N-072) where the layout check wanted `k` ("branch result
 * layout mismatch" / StackLowerFailed). Fail-closed, but legal code rejected.
 *
 * Fix: a post-pass drops the declared results of a terminal `if` (the last
 * binding of a public method body, recursively the last binding of a terminal
 * arm — the same rule 05-stack-lower uses for `terminalAssert`). Nothing can
 * read a result after the script's final verdict.
 *
 * The acceptance oracle is `@bsv/sdk`'s `Spend` under the consensus spend
 * context, fed each tier's own emitted hex. Every expected verdict is derived
 * by hand from the source, never from compiler output.
 *
 * What this proves: for each rebind shape below, each of the seven tiers
 * compiles the source, emits a script whose Spend verdict equals the source's
 * for all eight (a, b, c) witnesses in both constant-folding modes, and all
 * seven emit the same bytes. The non-terminal control keeps its exact
 * pre-fix bytes, so the post-pass does not touch a non-terminal `if`.
 * What it does NOT prove: stateful methods (the continuation follows the
 * `if`, so it is never terminal and is untouched); a stored `--ir` JSON that
 * still carries a terminal `if` with `results` (still refused by the existing
 * layout check / IR validator, unchanged); a private helper's own ANF body
 * is not post-processed, while an inlined copy inside a public body is if it
 * lands terminal — not exercised here.
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
const TMP = mkdtempSync(join(tmpdir(), 'runar-n261-'));
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
  // The item's literal shape: both arms rebind `k`, nothing reads it after.
  {
    name: 'T-rebind-both', body: `let k = 0n; if (c) { k = 1n; assert(a); } else { k = 2n; assert(b); }`,
    expect: (a, b, c) => (c ? a : b),
  },
  // Only the then-arm rebinds; the else-arm carries code, so pass 04 declares results [k].
  {
    name: 'T-rebind-then-only', body: `let k = 0n; if (c) { k = 1n; assert(a); } else { assert(b); }`,
    expect: (a, b, c) => (c ? a : b),
  },
  // The rebound value is READ inside the arm after the rebind: proves the arm keeps k's
  // value, not only the verdict. k == 0 + 2 always holds, so the else verdict is b.
  {
    name: 'T-rebind-read-in-arm', body: `let k = 0n; if (c) { k = k + 1n; assert(a); } else { k = k + 2n; assert(b); assert(k == 2n); }`,
    expect: (a, b, c) => (c ? a : b),
  },
  // Two merged locals (the mergedLocals >= 2 trigger in pass 04).
  {
    name: 'T-rebind-two-locals', body: `let k = 0n; let m = 0n; if (c) { k = 1n; m = 2n; assert(a); } else { m = 3n; assert(b); }`,
    expect: (a, b, c) => (c ? a : b),
  },
  // Nested terminal if: the inner if is terminal inside a terminal arm.
  {
    name: 'T-rebind-nested', body: `let k = 0n; if (c) { if (b) { k = 1n; assert(a); } else { k = 2n; assert(a); } } else { k = 3n; assert(b); }`,
    expect: (a, b, c) => (c ? a : b),
  },
  // Control: a NON-terminal if with declared results [k] (k dead after). It compiled and
  // spent correctly before the fix; its bytes are pinned from HEAD and must not move.
  {
    name: 'C-nonterminal-results', body: `let k = 0n; if (c) { k = 1n; } else { k = 2n; } assert(a);`,
    expect: (a) => a,
    pinnedHex: '52797600877c51879b69787600877c51879b69767600877c51879b69007c635176776752767768517a757b7777',
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
    describe(`N-261 [${shape.name}, fold ${fold ? 'on' : 'off'}] — terminal if may rebind a dead local`, () => {
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
