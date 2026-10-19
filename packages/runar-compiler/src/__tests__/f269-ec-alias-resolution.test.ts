/**
 * F-269 (CL-BUG-007) — the EC optimizer resolves through `@ref:` aliases, in
 * every tier (user decision R77).
 *
 * `@ref:<x>` aliases come from two places: the EC rules themselves (R1/R2/R3/R7
 * rewrite a call to `@ref:<operand>`) and pass 04, which lowers every
 * `const y = <expr>` to `t = <expr>; y = @ref:t`. The optimizer used to look a
 * name up with a plain map get, so an alias read as an opaque `load_const` and
 * no rule could see through it:
 *
 *     y  = ecAdd(x, INFINITY)    -- R1 rewrites to `y = @ref:x` (+ N-104 gate)
 *     nx = ecNegate(x)
 *     t  = ecAdd(y, nx)          -- R8 must see ecAdd(x, ecNegate(x)) -> INFINITY
 *
 * Every rule now follows alias chains, both to resolve an operand's value and
 * to decide whether two operands are "the same $x" (R8, R8r, R11). It does so
 * ONLY through names bound once in the method: ANF reuses a local's name when
 * the source reassigns it (`a = q` emits a second `a = @ref:..` binding, at
 * top level or inside an if/loop arm), so a chain through such a name can land
 * on a value the alias never held. A chain that would enter a rebound name, or
 * that cycles (hand-written `--ir`), is opaque — exactly the old behaviour.
 * Rewrites still EMIT the literal names they matched; only matching resolves.
 *
 * WHAT IT PROVES: (1) the brief's shape folds to the gated INFINITY in TS;
 * (2) each rule that consults an operand — R1, R3, R5/R6 via an aliased scalar,
 * R7, R8, R8r, R9, R10, R11, R12 — fires through an alias; (3) two rebinding
 * shapes lowered from real source, and an alias cycle, do NOT fold; (4) every
 * native tier compiles every probe, via `--ir`, to TS's exact script.
 *
 * WHAT IT DOES NOT PROVE: what the newly firing rewrites do at runtime. That is
 * executed against `@bsv/sdk`, optimized vs `disableEcOptimizer`, by
 * packages/runar-testing/src/__tests__/f269-ec-alias-rewrites-execution.test.ts.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, execSync } from 'child_process';
import { writeFileSync, mkdtempSync, rmSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { compile, compileFromANF } from '../index.js';
import { optimizeEC } from '../optimizer/anf-ec.js';
import type { ANFProgram, ANFBinding, ANFValue } from '../ir/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..', '..');

const INFINITY_HEX = '0'.repeat(128);
const G_HEX = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
            + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}
const ref = (x: string): ANFValue => ({ kind: 'load_const', value: `@ref:${x}` });
const call = (func: string, ...args: string[]): ANFValue => ({ kind: 'call', func, args });
const konst = (value: bigint | string): ANFValue => ({ kind: 'load_const', value });

function constructorMethod() {
  // Byte-for-byte the shape pass 04 emits for `constructor(tag) { super(tag); this.tag = tag; }`
  // — a different spelling makes the native `--ir` loaders reject the file.
  return {
    name: 'constructor',
    params: [{ name: 'tag', type: 'bigint' }],
    body: [
      b('c0', { kind: 'load_prop', name: 'tag' }),
      b('c1', { kind: 'call', func: 'super', args: ['c0'] }),
      b('c2', { kind: 'load_prop', name: 'tag' }),
      b('c3', { kind: 'update_prop', name: 'tag', value: 'c2' }),
    ],
    isPublic: false,
  };
}

/** `<body>` computing `t`, then `assert(t === expected)`. */
function probe(body: ANFBinding[], extraParams: { name: string; type: string }[] = []): ANFProgram {
  return {
    contractName: 'ECAliasProbe',
    properties: [{ name: 'tag', type: 'bigint', readonly: true }],
    methods: [
      constructorMethod(),
      {
        name: 'spend',
        params: [{ name: 'pt', type: 'Point' }, ...extraParams, { name: 'expected', type: 'Point' }],
        body: [
          ...body,
          b('e', { kind: 'load_param', name: 'expected' }),
          b('eq', { kind: 'bin_op', op: '===', left: 't', right: 'e', result_type: 'bytes' }),
          b('a', { kind: 'assert', value: 'eq' }),
        ],
        isPublic: true,
      },
    ],
  };
}

const X = b('x', { kind: 'load_param', name: 'pt' });

/** Each probe: an aliased spelling of one rule's match shape. */
const PROBES: Record<string, ANFProgram> = {
  // The brief's testable assertion: R1 produces the alias, R8 must see through it.
  'R8 through an R1-produced alias': probe([
    X,
    b('inf', konst(INFINITY_HEX)),
    b('y', call('ecAdd', 'x', 'inf')),
    b('nx', call('ecNegate', 'x')),
    b('t', call('ecAdd', 'y', 'nx')),
  ]),
  // pass 04's `const y = x` alias; Go binds $x to the ecNegate operand first.
  'R8r through a pass-04 alias': probe([
    X,
    b('y', ref('x')),
    b('nx', call('ecNegate', 'x')),
    b('t', call('ecAdd', 'nx', 'y')),
  ]),
  'R1 with an aliased INFINITY': probe([
    X,
    b('i0', konst(INFINITY_HEX)),
    b('inf', ref('i0')),
    b('t', call('ecAdd', 'x', 'inf')),
  ]),
  'R3 with an aliased scalar 1': probe([
    X,
    b('c', konst(1n)),
    b('one', ref('c')),
    b('t', call('ecMul', 'x', 'one')),
  ]),
  'R7 through an aliased inner ecNegate': probe([
    X,
    b('n1', call('ecNegate', 'x')),
    b('na', ref('n1')),
    b('t', call('ecNegate', 'na')),
  ]),
  'R9 through an aliased inner ecMul and aliased scalars': probe([
    X,
    b('k1', konst(2n)),
    b('ka', ref('k1')),
    b('m', call('ecMul', 'x', 'ka')),
    b('ma', ref('m')),
    b('k2', konst(3n)),
    b('kb', ref('k2')),
    b('t', call('ecMul', 'ma', 'kb')),
  ]),
  'R10 with aliased scalars': probe([
    b('k1', konst(2n)),
    b('ka', ref('k1')),
    b('g1', call('ecMulGen', 'ka')),
    b('k2', konst(5n)),
    b('g2', call('ecMulGen', 'k2')),
    b('ga', ref('g2')),
    b('t', call('ecAdd', 'g1', 'ga')),
  ]),
  'R11 with an aliased shared point': probe([
    X,
    b('y', ref('x')),
    b('k1', konst(2n)),
    b('k2', konst(3n)),
    b('m1', call('ecMul', 'x', 'k1')),
    b('m2', call('ecMul', 'y', 'k2')),
    b('t', call('ecAdd', 'm1', 'm2')),
  ]),
  'R12 with an aliased G (ecMulGen(aliased 1))': probe([
    b('c', konst(1n)),
    b('one', ref('c')),
    b('g', call('ecMulGen', 'one')),
    b('ga', ref('g')),
    b('k', konst(2n)),
    b('t', call('ecMul', 'ga', 'k')),
  ]),
  // NEGATIVE — the exact ANF pass 04 emits for
  //   let a = p; const y = a; a = q; ecAdd(y, ecNegate(a))
  // `a` is bound twice; y is p and a is q, so p + (-q) must NOT fold.
  'NEGATIVE: rebinding at top level': probe([
    b('t0', { kind: 'load_param', name: 'pt' }),
    b('av', ref('t0')),
    b('y', ref('av')),
    b('t1', { kind: 'load_param', name: 'q' }),
    b('av', ref('t1')),
    b('t2', call('ecNegate', 'av')),
    b('t', call('ecAdd', 'y', 't2')),
  ], [{ name: 'q', type: 'Point' }]),
};

/** The ANF TS's optimizer must leave for each positive probe (spend body, before the trailing assert). */
const NEG_CANCEL_GATE = (base: string, q: string) => [
  `${base}_px = call ecPointX ${q}`,
  `${base}_py = call ecPointY ${q}`,
  `${base}_zero = const 0`,
  `${base}_pxz = bin_op === ${base}_px ${base}_zero`,
  `${base}_pynz = bin_op !== ${base}_py ${base}_zero`,
  `${base}_ok = bin_op || ${base}_pxz ${base}_pynz`,
  `${base}_gate = assert ${base}_ok`,
];

function describeBinding(x: ANFBinding): string {
  const v = x.value;
  let d: string;
  switch (v.kind) {
    case 'load_param': d = `load_param ${v.name}`; break;
    case 'load_const':
      if (v.value === INFINITY_HEX) d = 'const INFINITY';
      else if (v.value === G_HEX) d = 'const G';
      else if (typeof v.value === 'string' && v.value.startsWith('@ref:')) d = `ref ${v.value.slice(5)}`;
      else d = `const ${String(v.value)}`;
      break;
    case 'call': d = `call ${v.func} ${v.args.join(' ')}`; break;
    case 'bin_op': d = `bin_op ${v.op} ${v.left} ${v.right}${v.result_type ? ` ${v.result_type}` : ''}`; break;
    case 'assert': d = `assert ${v.value}`; break;
    default: d = v.kind;
  }
  return `${x.name} = ${d}`;
}

function optimizedSpend(anf: ANFProgram): string[] {
  const out = optimizeEC(anf);
  return out.methods.find((m) => m.name === 'spend')!.body.map(describeBinding);
}

const TAIL = ['e = load_param expected', 'eq = bin_op === t e bytes', 'a = assert eq'];

const EXPECTED_TS: Record<string, string[]> = {
  'R8 through an R1-produced alias': [
    'x = load_param pt',
    'y_px = call ecPointX x', 'y_py = call ecPointY x',
    `y_fp = const ${0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn}`,
    'y_pxok = bin_op < y_px y_fp', 'y_pyok = bin_op < y_py y_fp',
    'y_ok = bin_op && y_pxok y_pyok', 'y_gate = assert y_ok',
    'y = ref x',
    'nx = call ecNegate x',
    ...NEG_CANCEL_GATE('t', 'y'),
    't = const INFINITY',
    ...TAIL,
  ],
  'R8r through a pass-04 alias': [
    'x = load_param pt',
    'nx = call ecNegate x',
    ...NEG_CANCEL_GATE('t', 'x'),
    't = const INFINITY',
    ...TAIL,
  ],
  'R7 through an aliased inner ecNegate': [
    'x = load_param pt',
    'n1 = call ecNegate x',
    't = ref x',
    ...TAIL,
  ],
  'R9 through an aliased inner ecMul and aliased scalars': [
    'x = load_param pt',
    'k1 = const 2', 'ka = ref k1', 'm = call ecMul x ka',
    't_k = const 6',
    't = call ecMul x t_k',
    ...TAIL,
  ],
  'R11 with an aliased shared point': [
    'x = load_param pt',
    'y = ref x',
    'k1 = const 2', 'k2 = const 3',
    // Every call is kept by DCE (it may abort); only the ecAdd is replaced.
    'm1 = call ecMul x k1', 'm2 = call ecMul y k2',
    't_k = const 5',
    't = call ecMul x t_k',
    ...TAIL,
  ],
};

describe('F-269: the EC optimizer resolves through @ref: aliases (TS reference)', () => {
  it("the brief's shape: R8 fires on ecAdd(y, ecNegate(x)) when y = @ref:x, and keeps the N-251 gate", () => {
    const out = optimizeEC(PROBES['R8 through an R1-produced alias']!);
    const t = out.methods.find((m) => m.name === 'spend')!.body.find((x) => x.name === 't')!;
    expect(t.value).toEqual({ kind: 'load_const', value: INFINITY_HEX });
  });

  for (const [name, expected] of Object.entries(EXPECTED_TS)) {
    it(`${name}: exact optimized ANF`, () => {
      expect(optimizedSpend(PROBES[name]!)).toEqual(expected);
    });
  }

  it('R1 / R3 with an aliased constant fire (the original call is gone)', () => {
    for (const name of ['R1 with an aliased INFINITY', 'R3 with an aliased scalar 1']) {
      const shape = optimizedSpend(PROBES[name]!);
      expect(shape, name).toContain('t = ref x');
      expect(shape, name).toContain('t_gate = assert t_ok');
    }
  });

  it('R10 / R12 with aliased scalars fire', () => {
    expect(optimizedSpend(PROBES['R10 with aliased scalars']!)).toContain('t = call ecMulGen t_k');
    expect(optimizedSpend(PROBES['R10 with aliased scalars']!)).toContain('t_k = const 7');
    expect(optimizedSpend(PROBES['R12 with an aliased G (ecMulGen(aliased 1))']!)).toContain('t = call ecMulGen k');
  });

  it('NEGATIVE: an alias through a rebound name is opaque — p + (-q) does not fold', () => {
    const shape = optimizedSpend(PROBES['NEGATIVE: rebinding at top level']!);
    expect(shape).toContain('t = call ecAdd y t2');
  });

  it('NEGATIVE: rebinding inside an if arm, lowered from source, does not fold', () => {
    const src = `
class IfReassign extends SmartContract {
  readonly expected: Point;
  constructor(expected: Point) { super(expected); this.expected = expected; }
  public unlock(p: Point, q: Point, c: boolean) {
    let a: Point = p;
    const y: Point = a;
    if (c) { a = q; }
    assert(ecAdd(y, ecNegate(a)) === this.expected);
  }
}
`;
    const r = compile(src, { disableConstantFolding: true });
    expect(r.success).toBe(true);
    const funcs = r.anf!.methods.find((m) => m.name === 'unlock')!.body
      .filter((x) => x.value.kind === 'call').map((x) => (x.value as { func: string }).func);
    expect(funcs).toContain('ecAdd');
  });

  it('NEGATIVE: an alias cycle (hand-written --ir) terminates and does not fold', () => {
    const anf = probe([
      X,
      b('p1', ref('p2')),
      b('p2', ref('p1')),
      b('nx', call('ecNegate', 'p2')),
      b('t', call('ecAdd', 'p1', 'nx')),
    ]);
    expect(optimizedSpend(anf)).toContain('t = call ecAdd p1 nx');
  });

  it('source level: `const g = ecMulGen(1n); ecMul(g, 2n)` now specializes to ecMulGen (R12)', () => {
    const src = `
class G2 extends SmartContract {
  readonly expected: Point;
  constructor(expected: Point) { super(expected); this.expected = expected; }
  public unlock() {
    const g = ecMulGen(1n);
    assert(ecMul(g, 2n) === this.expected);
  }
}
`;
    const r = compile(src, { disableConstantFolding: true });
    expect(r.success).toBe(true);
    const funcs = r.anf!.methods.find((m) => m.name === 'unlock')!.body
      .filter((x) => x.value.kind === 'call').map((x) => (x.value as { func: string }).func);
    expect(funcs).not.toContain('ecMul');
    expect(funcs).toContain('ecMulGen');
  });
});

// ---------------------------------------------------------------------------
// Cross-tier parity via --ir
// ---------------------------------------------------------------------------

/** Same bigint encoding the cross-compiler suite uses for the native IR decoders. */
function anfToJson(anf: ANFProgram): string {
  return JSON.stringify(anf, (_key, value) => {
    if (typeof value === 'bigint') {
      if (value >= Number.MIN_SAFE_INTEGER && value <= Number.MAX_SAFE_INTEGER) return Number(value);
      return value.toString() + 'n';
    }
    return value;
  }, 2);
}

interface Tier {
  id: string;
  /** Resolved command, or null when the toolchain is not installed locally. */
  binary: string | null;
  cwd: string;
  /** Zig's IR consumer is a positional subcommand and takes no fold flag. */
  args: (irPath: string) => string[];
  /** Zig interleaves allocator diagnostics; keep only the first line. */
  firstLineOnly?: boolean;
  env?: NodeJS.ProcessEnv;
}

/** Mirrors `cargoAwareEnv` in the conformance runner (not exported there). */
function cargoAwareEnv(): NodeJS.ProcessEnv {
  const home = process.env.HOME ?? '';
  const cargoBin = home ? `${home}/.cargo/bin` : '';
  const currentPath = process.env.PATH ?? '';
  return { ...process.env, PATH: cargoBin ? `${cargoBin}:${currentPath}` : currentPath };
}

// Binary discovery: the same candidate paths as conformance/runner/runner.ts,
// reduced to what an `--ir --hex` invocation needs (see
// r034-ec-negate-cancel-parity.test.ts). A tier whose toolchain is absent
// returns null and its tests skip.

function toolchainPresent(probeCmd: string): boolean {
  try {
    execSync(probeCmd, { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function firstExisting(...paths: string[]): string | null {
  for (const p of paths) if (existsSync(p)) return p;
  return null;
}

function findGoBinary(): string | null {
  const built = firstExisting(join(REPO_ROOT, 'compilers', 'go', 'runar-go'));
  if (built) return built;
  return toolchainPresent('go version') ? 'go run .' : null;
}

function findRustBinary(): string | null {
  return firstExisting(
    join(REPO_ROOT, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'),
    join(REPO_ROOT, 'compilers', 'rust', 'target', 'debug', 'runar-compiler-rust'),
  );
}

function findPythonBinary(): string | null {
  if (!existsSync(join(REPO_ROOT, 'compilers', 'python', 'runar_compiler', '__main__.py'))) return null;
  return toolchainPresent('python3 --version') ? 'python3 -m runar_compiler' : null;
}

function findZigBinary(): string | null {
  return firstExisting(join(REPO_ROOT, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'));
}

function findRubyBinary(): string | null {
  const script = join(REPO_ROOT, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby');
  if (!existsSync(script)) return null;
  return toolchainPresent('ruby --version') ? `ruby ${script}` : null;
}

function findJavaBinary(): string | null {
  const libsDir = join(REPO_ROOT, 'compilers', 'java', 'build', 'libs');
  if (!existsSync(libsDir)) return null;
  const jar = firstExisting(
    join(libsDir, 'runar-java.jar'),
    ...readdirSync(libsDir)
      .filter((e) => e.startsWith('runar-java-compiler-') && e.endsWith('.jar'))
      .map((e) => join(libsDir, e)),
  );
  if (!jar) return null;
  return toolchainPresent('java -version') ? `java -jar ${jar}` : null;
}

function irArgs(irPath: string): string[] {
  return ['--ir', irPath, '--hex', '--disable-constant-folding'];
}

const TIERS: Tier[] = [
  { id: 'go', binary: findGoBinary(), cwd: join(REPO_ROOT, 'compilers', 'go'), args: irArgs },
  { id: 'rust', binary: findRustBinary(), cwd: join(REPO_ROOT, 'compilers', 'rust'), args: irArgs, env: cargoAwareEnv() },
  { id: 'python', binary: findPythonBinary(), cwd: join(REPO_ROOT, 'compilers', 'python'), args: irArgs },
  {
    id: 'zig',
    binary: findZigBinary(),
    cwd: join(REPO_ROOT, 'compilers', 'zig'),
    args: (p) => ['compile-ir', p, '--hex'],
    firstLineOnly: true,
  },
  { id: 'ruby', binary: findRubyBinary(), cwd: join(REPO_ROOT, 'compilers', 'ruby'), args: irArgs },
  { id: 'java', binary: findJavaBinary(), cwd: join(REPO_ROOT, 'compilers', 'java'), args: irArgs },
];

function runTier(tier: Tier, irPath: string): string {
  const parts = tier.binary!.split(/\s+/);
  const out = execFileSync(parts[0]!, [...parts.slice(1), ...tier.args(irPath)], {
    cwd: tier.cwd,
    env: tier.env,
    timeout: 600_000,
    maxBuffer: 128 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  }).toString();
  const raw = tier.firstLineOnly ? (out.split('\n')[0] ?? '') : out;
  return raw.replace(/\s/g, '').toLowerCase();
}

/** Compare without handing vitest two ~26 KB hex strings to diff. */
function expectSameHex(label: string, a: string, bHex: string): void {
  if (a === bHex) return;
  let i = 0;
  while (i < a.length && i < bHex.length && a[i] === bHex[i]) i++;
  throw new Error(
    `${label}: hex differs. lenA=${a.length} lenB=${bHex.length} firstDiffAt=${i}\n` +
    `  a: ...${a.slice(Math.max(0, i - 16), i + 16)}...\n` +
    `  b: ...${bHex.slice(Math.max(0, i - 16), i + 16)}...`,
  );
}

// ---------------------------------------------------------------------------
// F-269 attempt 2: identity and lifted operands through REBOUND names
// ---------------------------------------------------------------------------
//
// The first attempt made a rebound name canonical to itself, so two literal
// uses of a rebound `a` at different positions compared "the same binding",
// and an operand lifted out of an earlier binding (`nx = ecNegate(a)`) was
// re-emitted at a later site where `a` holds a different value. Every shape
// below is the ANF pass 04 emits for the source shown (optimizer off), and
// each must now compile to exactly the unoptimized script: no rule may fire.
// The `--ir` "de-aliased" variants replace the `const` alias with its target
// (`nx` -> the ecNegate binding itself) — the raw-name form of N-352, which
// fired before F-269 too.

const rebindSrc = (name: string, body: string, params = 'p: Point, q: Point') => `
class ${name} extends SmartContract {
  constructor() { super(); }
  public unlock(${params}, e: Point) {
${body}
  }
}
`;

const REBIND_SOURCES: Record<string, { src: string; deAlias?: string[] }> = {
  'R8 rebind via const nx': { src: rebindSrc('R8Top', '    let a: Point = p;\n    const nx: Point = ecNegate(a);\n    a = q;\n    assert(ecAdd(a, nx) === e);') },
  'R8r rebind via const nx': { src: rebindSrc('R8rTop', '    let a: Point = p;\n    const nx: Point = ecNegate(a);\n    a = q;\n    assert(ecAdd(nx, a) === e);') },
  'R7 rebind via const n': { src: rebindSrc('R7Top', '    let a: Point = p;\n    const n: Point = ecNegate(a);\n    a = q;\n    assert(ecNegate(n) === e);') },
  'R9 rebind via const m': { src: rebindSrc('R9Top', '    let a: Point = p;\n    const m: Point = ecMul(a, 2n);\n    a = q;\n    assert(ecMul(m, 3n) === e);') },
  'R11 rebind (same name, different values)': { src: rebindSrc('R11Top', '    let a: Point = p;\n    const l: Point = ecMul(a, 2n);\n    a = q;\n    const r: Point = ecMul(a, 3n);\n    assert(ecAdd(l, r) === e);') },
  'R8 rebind in an if arm': { src: rebindSrc('R8If', '    let a: Point = p;\n    const nx: Point = ecNegate(a);\n    if (c) { a = q; }\n    assert(ecAdd(a, nx) === e);', 'p: Point, q: Point, c: boolean') },
  'R8 rebind in a loop': { src: rebindSrc('R8Loop', '    let a: Point = p;\n    const nx: Point = ecNegate(a);\n    for (let i = 0n; i < 1n; i++) { a = q; }\n    assert(ecAdd(a, nx) === e);') },
  'R8 two aliases of one rebound name (N-353 aliased)': { src: rebindSrc('GoEqAlias', '    let t: Point = p;\n    const a: Point = t;\n    t = q;\n    const b: Point = t;\n    const nb: Point = ecNegate(b);\n    assert(ecAdd(a, nb) === e);') },
  'R8 two aliases of one rebound name (N-353 direct)': { src: rebindSrc('GoEqDirect', '    let t: Point = p;\n    const a: Point = t;\n    t = q;\n    const b: Point = t;\n    assert(ecAdd(a, ecNegate(b)) === e);') },
  '--ir de-aliased R7 (N-352)': { src: rebindSrc('R7Ir', '    let a: Point = p;\n    const n: Point = ecNegate(a);\n    a = q;\n    assert(ecNegate(n) === e);'), deAlias: ['n'] },
  '--ir de-aliased R8 (N-352)': { src: rebindSrc('R8Ir', '    let a: Point = p;\n    const nx: Point = ecNegate(a);\n    a = q;\n    assert(ecAdd(a, nx) === e);'), deAlias: ['nx'] },
  '--ir de-aliased R8r (N-352)': { src: rebindSrc('R8rIr', '    let a: Point = p;\n    const nx: Point = ecNegate(a);\n    a = q;\n    assert(ecAdd(nx, a) === e);'), deAlias: ['nx'] },
  '--ir de-aliased R9 (N-352)': { src: rebindSrc('R9Ir', '    let a: Point = p;\n    const m: Point = ecMul(a, 2n);\n    a = q;\n    assert(ecMul(m, 3n) === e);'), deAlias: ['m'] },
  '--ir de-aliased R11 (N-352)': { src: rebindSrc('R11Ir', '    let a: Point = p;\n    const l: Point = ecMul(a, 2n);\n    a = q;\n    const r: Point = ecMul(a, 3n);\n    assert(ecAdd(l, r) === e);'), deAlias: ['l', 'r'] },
};

/** Pass-04 ANF for `src` (no optimizer), with the named `const` aliases replaced by their targets in call args. */
function rebindAnf(src: string, deAlias: string[] = []): ANFProgram {
  const r = compile(src, { disableConstantFolding: true, disableEcOptimizer: true });
  if (!r.success || !r.anf) throw new Error(`rebind probe failed to compile: ${JSON.stringify(r.diagnostics)}`);
  const anf = structuredClone(r.anf);
  const m = anf.methods.find((x) => x.name === 'unlock')!;
  for (const alias of deAlias) {
    const v = m.body.find((x) => x.name === alias)!.value as { kind: string; value: string };
    const target = v.value.slice(5);
    for (const x of m.body) if (x.value.kind === 'call') x.value.args = x.value.args.map((a) => (a === alias ? target : a));
    // Drop the now-unused alias: tiers differ on whether DCE runs when no
    // rule fires (a pre-existing gate difference), which is not this probe.
    m.body = m.body.filter((x) => x.name !== alias);
  }
  return anf;
}

const REBIND_PROBES: Record<string, ANFProgram> = Object.fromEntries(
  Object.entries(REBIND_SOURCES).map(([name, { src, deAlias }]) => [name, rebindAnf(src, deAlias)]),
);

describe('F-269: no identity or lifted operand through a rebound name (TS reference)', () => {
  for (const [name, anf] of Object.entries(REBIND_PROBES)) {
    it(`${name}: no rule fires (optimized script === unoptimized script)`, () => {
      const opt = compileFromANF(structuredClone(anf), { disableConstantFolding: true }).scriptHex as string;
      const unopt = compileFromANF(structuredClone(anf), { disableConstantFolding: true, disableEcOptimizer: true }).scriptHex as string;
      expect(opt === unopt, `${name}: optimized ${opt.length / 2} bytes vs unoptimized ${unopt.length / 2}`).toBe(true);
    });
  }
});

const ALL_PROBES: Record<string, ANFProgram> = { ...PROBES, ...REBIND_PROBES };

describe('F-269: every native tier resolves aliases exactly as TS does (--ir parity)', () => {
  let tempDir: string;
  const irPaths: Record<string, string> = {};
  const tsHex: Record<string, string> = {};

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-f269-'));
    let i = 0;
    for (const [name, anf] of Object.entries(ALL_PROBES)) {
      const p = join(tempDir, `probe${i++}.anf.json`);
      writeFileSync(p, anfToJson(anf));
      irPaths[name] = p;
      tsHex[name] = (compileFromANF(anf, { disableConstantFolding: true }).scriptHex as string).toLowerCase();
    }
  });

  afterAll(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  for (const tier of TIERS) {
    describe.skipIf(tier.binary === null)(tier.id, () => {
      for (const name of Object.keys(ALL_PROBES)) {
        it(`${name} matches TS`, () => {
          expectSameHex(`ts vs ${tier.id}: ${name}`, tsHex[name]!, runTier(tier, irPaths[name]!));
        });
      }
    });
  }
}, 900_000);
