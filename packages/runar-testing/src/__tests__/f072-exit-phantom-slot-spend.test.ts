/**
 * F-072 — execution proof, all seven tiers: `exit(cond)` followed by more code
 * reads the right stack slots.
 *
 *     public check(b: bigint, a: bigint, x: bigint, y: bigint) {
 *       exit(x > 0n);
 *       assert(y === 1n);
 *       assert(a > 5n);
 *       assert(b === 0n);
 *     }
 *
 * `exit(cond)` has no dedicated ANF node; it lowers as `call exit`, and every
 * tier's lowerCall ran `cond OP_VERIFY` and then pushed a stack-map slot for
 * the call's (void) result. OP_VERIFY leaves nothing behind, so the model had
 * one slot the machine did not: every later PICK/ROLL addressed the item one
 * below the one it meant, and the end-of-method cleanup NIPped an item that
 * was never there. Every tier emitted the same wrong bytes
 *
 *     7c00a0697c519d7c55a0697c9177
 *     SWAP 0 GT VERIFY SWAP 1 NUMEQUALVERIFY SWAP 5 GT VERIFY SWAP NOT NIP
 *
 * which rejects the honest witness (b=0, a=6, x=1, y=1) and ACCEPTS a
 * five-push witness (0, b=6, a=1, x=1, y=999): `y === 1` checks a,
 * `a > 5` checks b, `b === 0` checks the smuggled extra item, and the final
 * NIP removes y. The source forbids y=999, a=1 and b=6.
 *
 * The same phantom push sat in lowerCall's `assert` branch (reachable through
 * `--ir` as `call assert`; the frontends emit the dedicated `assert` node) and
 * its `super` branch (dead: constructors are never stack-lowered and every
 * loader refuses `super` outside a constructor — conformance negative I14).
 *
 * The expected scripts are derived by hand from the source, and each equals
 * the bytes of the same contract written with `assert` in place of `exit` —
 * `exit(c)` is specified as `c OP_VERIFY`, the same as a non-terminal assert:
 *
 *     ExitAssert  (x, y)        7c00a069519c           SWAP 0 GT VERIFY 1 NUMEQUAL
 *     ExitAssert3 (a, x, y)     7c00a069519d55a0       ... 1 NUMEQUALVERIFY 5 GT
 *     ExitAssert4 (b, a, x, y)  7c00a069519d55a06991   ... 5 GT VERIFY NOT
 *
 * Oracle: `@bsv/sdk` Spend under the strict consensus rule set
 * (`newConsensusSpend`: push-only, clean stack, minimal pushes) — never
 * TestContract or the ANF interpreter, which share the compiler's model.
 *
 * What this proves: in every tier, in both constant-folding modes (source
 * path) and on the `--ir` path (`call exit` and `call assert`), the compiled
 * script accepts the honest witnesses, rejects the crafted witness the pre-fix
 * bytes accepted, and all seven tiers emit identical bytes equal to the
 * hand-derived script. The pre-fix bytes are run through the same harness to
 * show the harness itself tells the two apart. `exit()` as the LAST statement
 * is refused by every tier's validator (a public method must end with
 * assert), so there is no source-level exit-last program to execute; that
 * refusal is pinned as the control.
 * What it does NOT prove: `exit()` inside `if` arms or loop bodies — no
 * separate spend here; those go through the same lowerCall branch.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import { compile, compileFromANF, loadANFFromJSON } from 'runar-compiler';
import { newConsensusSpend, CONSENSUS_SPEND_CONTEXT } from '../consensus-spend.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-f072-'));

function contract(name: string, params: string[], body: string[]): string {
  return `import { SmartContract, assert } from 'runar-lang';

class ${name} extends SmartContract {
  constructor() {
    super();
  }

  public check(${params.map((p) => `${p}: bigint`).join(', ')}) {
${body.map((s) => `    ${s}`).join('\n')}
  }
}
`;
}

interface Case {
  name: string;
  params: string[];
  body: string[];
  preFixHex: string;
  expectedHex: string;
  /** Witnesses the source allows (param order). */
  honest: bigint[][];
  /** Witnesses the source forbids; the first one is accepted by preFixHex. */
  forbidden: bigint[][];
}

const CASES: Case[] = [
  {
    name: 'ExitAssert',
    params: ['x', 'y'],
    body: ['exit(x > 0n);', 'assert(y === 1n);'],
    preFixHex: '7c00a0697c519c77',
    expectedHex: '7c00a069519c',
    honest: [[1n, 1n], [5n, 1n]],
    // Pre-fix every spend underflows OP_SWAP, the honest one included (locked
    // funds rather than stolen ones), so this case has no accepting attack.
    forbidden: [[0n, 1n], [1n, 2n], [1n, 999n]],
  },
  {
    name: 'ExitAssert3',
    params: ['a', 'x', 'y'],
    body: ['exit(x > 0n);', 'assert(y === 1n);', 'assert(a > 5n);'],
    preFixHex: '7c00a0697c519d7c55a077',
    expectedHex: '7c00a069519d55a0',
    honest: [[6n, 1n, 1n], [9n, 3n, 1n]],
    forbidden: [[6n, 1n, 1n, 999n], [6n, 0n, 1n], [6n, 1n, 2n], [5n, 1n, 1n]],
  },
  {
    name: 'ExitAssert4',
    params: ['b', 'a', 'x', 'y'],
    body: ['exit(x > 0n);', 'assert(y === 1n);', 'assert(a > 5n);', 'assert(b === 0n);'],
    preFixHex: '7c00a0697c519d7c55a0697c9177',
    expectedHex: '7c00a069519d55a06991',
    honest: [[0n, 6n, 1n, 1n]],
    forbidden: [[0n, 6n, 1n, 1n, 999n], [0n, 6n, 0n, 1n], [0n, 6n, 1n, 2n], [0n, 5n, 1n, 1n], [1n, 6n, 1n, 1n]],
  },
];

/** Minimal push of a script number. */
function pushNum(n: bigint): string {
  if (n === 0n) return '00';
  if (n >= 1n && n <= 16n) return (0x50 + Number(n)).toString(16);
  if (n < 0n) throw new Error('pushNum: negative values not needed here');
  const bytes: number[] = [];
  let v = n;
  while (v > 0n) {
    bytes.push(Number(v & 0xffn));
    v >>= 8n;
  }
  if (bytes[bytes.length - 1]! & 0x80) bytes.push(0);
  return bytes.length.toString(16).padStart(2, '0') + bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

function spends(lockingHex: string, witness: bigint[]): boolean {
  const unlocking = witness.map(pushNum).join('');
  try {
    const s = newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(unlocking),
      otherInputs: [],
      outputs: [],
    });
    return s.validate();
  } catch {
    return false;
  }
}

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

interface RunResult { status: number | null; stdout: string; stderr: string }

function exec(cmd: string, args: string[], cwd?: string): RunResult {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 32 * 1024 * 1024 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  return { status: r.status, stdout: r.stdout.trim(), stderr: r.stderr };
}

function hexOf(cmd: string, args: string[], cwd?: string): string {
  const r = exec(cmd, args, cwd);
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}: ${r.stderr}`);
  const lines = r.stdout.split('\n');
  return lines[lines.length - 1]!.trim();
}

let seq = 0;
function writeTmp(fileName: string, src: string): string {
  const dir = join(TMP, String(seq++));
  mkdirSync(dir);
  const p = join(dir, fileName);
  writeFileSync(p, src);
  return p;
}

const FOLD_OFF = ['--disable-constant-folding'];
const GO = () => requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .');
const RUST = () => requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release');
const ZIG = () => requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build');
const RUBY_ARGS = () => ['-I', join(REPO, 'compilers', 'ruby', 'lib'), join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')];
const PY_CWD = join(REPO, 'compilers', 'python');

/** Source-path CLI invocation per non-TS tier: (file, fold) → [cmd, args, cwd]. */
const SOURCE_CLIS: { name: string; argv: (file: string, fold: boolean) => [string, string[], string?] }[] = [
  { name: 'go', argv: (f, fold) => [GO(), ['--source', f, '--hex', ...(fold ? [] : FOLD_OFF)]] },
  { name: 'rust', argv: (f, fold) => [RUST(), ['--source', f, '--hex', ...(fold ? [] : FOLD_OFF)]] },
  { name: 'python', argv: (f, fold) => ['python3', ['-m', 'runar_compiler', '--source', f, '--hex', ...(fold ? [] : FOLD_OFF)], PY_CWD] },
  { name: 'zig', argv: (f, fold) => [ZIG(), ['--source', f, '--hex', ...(fold ? [] : FOLD_OFF)]] },
  { name: 'ruby', argv: (f, fold) => ['ruby', [...RUBY_ARGS(), '--source', f, '--hex', ...(fold ? [] : FOLD_OFF)]] },
  { name: 'java', argv: (f, fold) => ['java', ['-jar', javaJar(), '--source', f, '--hex', ...(fold ? [] : FOLD_OFF)]] },
];

/** `--ir` CLI invocation per non-TS tier. Zig's IR consumer is `compile-ir <file>`. */
const IR_CLIS: { name: string; argv: (file: string) => [string, string[], string?] }[] = [
  { name: 'go', argv: (f) => [GO(), ['--ir', f, '--hex']] },
  { name: 'rust', argv: (f) => [RUST(), ['--ir', f, '--hex']] },
  { name: 'python', argv: (f) => ['python3', ['-m', 'runar_compiler', '--ir', f, '--hex'], PY_CWD] },
  { name: 'zig', argv: (f) => [ZIG(), ['compile-ir', f, '--hex']] },
  { name: 'ruby', argv: (f) => ['ruby', [...RUBY_ARGS(), '--ir', f, '--hex']] },
  { name: 'java', argv: (f) => ['java', ['-jar', javaJar(), '--ir', f, '--hex']] },
];

function tsSourceHex(src: string, fileName: string, fold: boolean): string {
  const r = compile(src, { fileName, disableConstantFolding: !fold });
  if (!r.success || !r.scriptHex) throw new Error(JSON.stringify(r.diagnostics));
  return r.scriptHex;
}

/** Every tier's hex for `src`, keyed by tier name. */
function allTiersSource(src: string, fileName: string, fold: boolean): Record<string, string> {
  const out: Record<string, string> = { ts: tsSourceHex(src, fileName, fold) };
  const file = writeTmp(fileName, src);
  for (const cli of SOURCE_CLIS) {
    const [cmd, args, cwd] = cli.argv(file, fold);
    out[cli.name] = hexOf(cmd, args, cwd);
  }
  return out;
}

/**
 * ANF IR for ExitAssert4 with its first guard as `call <func>` — `exit` is
 * what every frontend emits; `assert` is the `--ir`-only spelling that hits
 * lowerCall's assert branch instead of the dedicated `assert` node.
 */
function exitAssert4Ir(func: 'exit' | 'assert'): string {
  const b = (name: string, value: Record<string, unknown>) => ({ name, value });
  return JSON.stringify({
    contractName: 'ExitAssert4',
    properties: [],
    methods: [
      { name: 'constructor', params: [], isPublic: false, body: [b('t0', { kind: 'call', func: 'super', args: [] })] },
      {
        name: 'check',
        isPublic: true,
        params: ['b', 'a', 'x', 'y'].map((n) => ({ name: n, type: 'bigint' })),
        body: [
          b('t0', { kind: 'load_param', name: 'x' }),
          b('t1', { kind: 'load_const', value: 0 }),
          b('t2', { kind: 'bin_op', op: '>', left: 't0', right: 't1' }),
          b('t3', { kind: 'call', func, args: ['t2'] }),
          b('t4', { kind: 'load_param', name: 'y' }),
          b('t5', { kind: 'load_const', value: 1 }),
          b('t6', { kind: 'bin_op', op: '===', left: 't4', right: 't5' }),
          b('t7', { kind: 'assert', value: 't6' }),
          b('t8', { kind: 'load_param', name: 'a' }),
          b('t9', { kind: 'load_const', value: 5 }),
          b('t10', { kind: 'bin_op', op: '>', left: 't8', right: 't9' }),
          b('t11', { kind: 'assert', value: 't10' }),
          b('t12', { kind: 'load_param', name: 'b' }),
          b('t13', { kind: 'load_const', value: 0 }),
          b('t14', { kind: 'bin_op', op: '===', left: 't12', right: 't13' }),
          b('t15', { kind: 'assert', value: 't14' }),
        ],
      },
    ],
  });
}

function allTiersIr(json: string): Record<string, string> {
  const r = compileFromANF(loadANFFromJSON(json));
  const out: Record<string, string> = { ts: r.scriptHex };
  const file = writeTmp('ExitAssert4.ir.json', json);
  for (const cli of IR_CLIS) {
    const [cmd, args, cwd] = cli.argv(file);
    out[cli.name] = hexOf(cmd, args, cwd);
  }
  return out;
}

const EA4 = CASES[2]!;

function checkVerdicts(c: Case, hex: string): void {
  for (const w of c.honest) expect(spends(hex, w), `honest ${w.join(',')}`).toBe(true);
  for (const w of c.forbidden) expect(spends(hex, w), `forbidden ${w.join(',')}`).toBe(false);
}

describe('F-072 — exit() followed by more code reads the right stack slots', () => {
  it('the harness distinguishes: the pre-fix bytes reject the honest witness and accept the crafted one', () => {
    // Non-vacuity: a reject/accept below is the fix, not the harness.
    for (const c of CASES) {
      for (const w of c.honest) expect(spends(c.preFixHex, w), `${c.name} honest ${w.join(',')}`).toBe(false);
    }
    expect(spends(CASES[1]!.preFixHex, CASES[1]!.forbidden[0]!)).toBe(true);
    expect(spends(EA4.preFixHex, EA4.forbidden[0]!)).toBe(true);
    // And the expected bytes are not vacuously strict.
    for (const c of CASES) expect(spends(c.expectedHex, c.honest[0]!)).toBe(true);
  });

  for (const c of CASES) {
    for (const fold of [false, true]) {
      it(`${c.name} (fold ${fold ? 'ON' : 'OFF'}): all seven tiers emit the hand-derived script and it spends correctly`, () => {
        const hexes = allTiersSource(contract(c.name, c.params, c.body), `${c.name}.runar.ts`, fold);
        for (const [tier, hex] of Object.entries(hexes)) {
          expect(hex, `${tier}`).not.toBe(c.preFixHex);
          checkVerdicts(c, hex);
          expect(hex, `${tier}`).toBe(c.expectedHex);
        }
      }, 180_000);

      it(`${c.name} (fold ${fold ? 'ON' : 'OFF'}) control: exit(c) compiles exactly like a non-terminal assert(c)`, () => {
        const body = c.body.map((s) => s.replace(/^exit\(/, 'assert('));
        const hexes = allTiersSource(contract(`${c.name}Ctl`, c.params, body), `${c.name}Ctl.runar.ts`, fold);
        for (const [tier, hex] of Object.entries(hexes)) expect(hex, `${tier}`).toBe(c.expectedHex);
      }, 180_000);
    }
  }

  for (const func of ['exit', 'assert'] as const) {
    it(`--ir: \`call ${func}\` followed by more code — all seven tiers emit the hand-derived script`, () => {
      const hexes = allTiersIr(exitAssert4Ir(func));
      for (const [tier, hex] of Object.entries(hexes)) {
        checkVerdicts(EA4, hex);
        expect(hex, `${tier}`).toBe(EA4.expectedHex);
      }
    }, 180_000);
  }

  it('control: exit() as the last statement is refused by every tier (a public method must end with assert)', () => {
    const src = contract('ExitLast', ['x', 'y'], ['assert(y === 1n);', 'exit(x > 0n);']);
    const r = compile(src, { fileName: 'ExitLast.runar.ts' });
    expect(r.success).toBe(false);
    const file = writeTmp('ExitLast.runar.ts', src);
    for (const cli of SOURCE_CLIS) {
      const [cmd, args, cwd] = cli.argv(file, true);
      expect(exec(cmd, args, cwd).status, cli.name).not.toBe(0);
    }
  }, 180_000);
});
