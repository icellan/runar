/**
 * F-115 — the TS EC optimizer runs to a fixed point, like the other six tiers.
 *
 * Go, Rust, Python, Zig, Ruby and Java re-scan a method until no EC rule fires.
 * `optimizeMethodEC` in optimizer/anf-ec.ts made ONE pass, and `tryRewrite`
 * applies at most one rule per binding, so a binding whose REWRITTEN value
 * matches another rule was left half-reduced in TS only. Each probe below is a
 * two-step chain on one binding:
 *
 *     10 -> 5   ecAdd(ecMulGen(n-7), ecMulGen(7))   -> ecMulGen(0)    -> INFINITY
 *     10 -> 6   ecAdd(ecMulGen(n-6), ecMulGen(7))   -> ecMulGen(1)    -> G
 *     11 -> 4   ecAdd(ecMul(p, 3), ecMul(p, n-3))   -> ecMul(p, 0)    -> INFINITY + gate
 *      9 -> 3   ecMul(ecMul(p, 3), 3^-1 mod n)      -> ecMul(p, 1)    -> p + gate
 *
 * Single pass, TS stopped at the middle column and emitted a runtime EC
 * multiplication for a compile-time constant; 10 -> 5 alone was a 1,276,385-byte
 * script against the other tiers' 851,001 bytes.
 * (N-113 has since removed the two dead inner `ecMulGen` calls of the 10 -> 5
 * and 10 -> 6 chains in every tier: 10 -> 5 is now a 67-byte script.)
 *
 * WHAT IT PROVES: TS reaches the same fully reduced ANF (names, kinds, operands,
 * order) for each chain, and every native tier compiles the same probe ANF
 * (via `--ir`) to the same script hex as TS. The source-level ANF + hex parity of
 * the 10 -> 5 chain across 7 tiers x 9 formats is pinned by the conformance
 * fixture `ec-chained-rewrite`.
 *
 * WHAT IT DOES NOT PROVE: that the rules themselves are sound (each rule has its
 * own tests), or the runtime behaviour of the folded script. The fixture's
 * real-crypto witness executes that on @bsv/sdk's Spend engine.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, execSync } from 'child_process';
import { writeFileSync, mkdtempSync, rmSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { compileFromANF } from '../index.js';
import { optimizeEC } from '../optimizer/anf-ec.js';
import type { ANFProgram, ANFBinding, ANFValue } from '../ir/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..', '..');

const CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const INFINITY_HEX = '0'.repeat(128);
const G_HEX =
  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
  '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let r = 1n;
  let x = base % m;
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * x) % m;
    x = (x * x) % m;
  }
  return r;
}
const INV3 = modPow(3n, CURVE_N - 2n, CURVE_N);

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

type Chain = '10->5' | '10->6' | '11->4' | '9->3';
const CHAINS: Chain[] = ['10->5', '10->6', '11->4', '9->3'];

/** The chained expression bound to `t`, then `assert(t === pt)`. */
function probeBody(chain: Chain): ANFBinding[] {
  const head: Record<Chain, ANFBinding[]> = {
    '10->5': [
      b('k1', { kind: 'load_const', value: CURVE_N - 7n }),
      b('g1', { kind: 'call', func: 'ecMulGen', args: ['k1'] }),
      b('k2', { kind: 'load_const', value: 7n }),
      b('g2', { kind: 'call', func: 'ecMulGen', args: ['k2'] }),
      b('t', { kind: 'call', func: 'ecAdd', args: ['g1', 'g2'] }),
    ],
    '10->6': [
      b('k1', { kind: 'load_const', value: CURVE_N - 6n }),
      b('g1', { kind: 'call', func: 'ecMulGen', args: ['k1'] }),
      b('k2', { kind: 'load_const', value: 7n }),
      b('g2', { kind: 'call', func: 'ecMulGen', args: ['k2'] }),
      b('t', { kind: 'call', func: 'ecAdd', args: ['g1', 'g2'] }),
    ],
    '11->4': [
      b('k1', { kind: 'load_const', value: 3n }),
      b('m1', { kind: 'call', func: 'ecMul', args: ['p', 'k1'] }),
      b('k2', { kind: 'load_const', value: CURVE_N - 3n }),
      b('m2', { kind: 'call', func: 'ecMul', args: ['p', 'k2'] }),
      b('t', { kind: 'call', func: 'ecAdd', args: ['m1', 'm2'] }),
    ],
    '9->3': [
      b('k1', { kind: 'load_const', value: 3n }),
      b('m1', { kind: 'call', func: 'ecMul', args: ['p', 'k1'] }),
      b('k2', { kind: 'load_const', value: INV3 }),
      b('t', { kind: 'call', func: 'ecMul', args: ['m1', 'k2'] }),
    ],
  };
  return [
    b('p', { kind: 'load_param', name: 'pt' }),
    ...head[chain],
    b('q', { kind: 'load_param', name: 'expected' }),
    b('eq', { kind: 'bin_op', op: '===', left: 't', right: 'q', result_type: 'bytes' }),
    b('a', { kind: 'assert', value: 'eq' }),
  ];
}

function probeProgram(chain: Chain): ANFProgram {
  return {
    contractName: 'ECChainProbe',
    properties: [{ name: 'tag', type: 'bigint', readonly: true }],
    methods: [
      {
        // The shape pass 04 emits for `constructor(tag) { super(tag); this.tag = tag; }`,
        // so the native `--ir` loaders accept the file.
        name: 'constructor',
        params: [{ name: 'tag', type: 'bigint' }],
        body: [
          b('c0', { kind: 'load_prop', name: 'tag' }),
          b('c1', { kind: 'call', func: 'super', args: ['c0'] }),
          b('c2', { kind: 'load_prop', name: 'tag' }),
          b('c3', { kind: 'update_prop', name: 'tag', value: 'c2' }),
        ],
        isPublic: false,
      },
      {
        name: 'spend',
        params: [{ name: 'pt', type: 'Point' }, { name: 'expected', type: 'Point' }],
        body: probeBody(chain),
        isPublic: true,
      },
    ],
  };
}

function describeBinding(x: ANFBinding): string {
  const v = x.value;
  switch (v.kind) {
    case 'load_param': return `${x.name} = load_param ${v.name}`;
    case 'load_const':
      if (v.value === INFINITY_HEX) return `${x.name} = const INFINITY`;
      if (v.value === G_HEX) return `${x.name} = const G`;
      if (typeof v.value === 'string' && v.value.startsWith('@ref:')) return `${x.name} = ref ${v.value.slice(5)}`;
      return `${x.name} = const ${String(v.value)}`;
    case 'call': return `${x.name} = call ${v.func} ${v.args.join(' ')}`;
    case 'bin_op': return `${x.name} = bin_op ${v.op} ${v.left} ${v.right}${v.result_type ? ` ${v.result_type}` : ''}`;
    case 'assert': return `${x.name} = assert ${v.value}`;
    default: return `${x.name} = ${v.kind}`;
  }
}

const TAIL = ['q = load_param expected', 'eq = bin_op === t q bytes', 'a = assert eq'];
const MUL_GATE_ON_P = [
  't_inf = const INFINITY',
  't_isinf = bin_op === p t_inf bytes',
  't_oncurve = call ecOnCurve p',
  't_ok = bin_op || t_isinf t_oncurve',
  't_gate = assert t_ok',
];

// The superseded inner ecMul calls survive DCE (calls are conservatively
// effectful, and after the second rewrite no surviving ecMul on p performs
// their operand gate); the fused scalar `t_k` does not, because the second
// rewrite stops reading it. N-113: the superseded inner `ecMulGen(<const>)`
// calls of the two R10 chains DO go — they cannot abort — and their scalars
// with them.
const EXPECTED: Record<Chain, string[]> = {
  // `p` is unread in the two ecMulGen chains, so DCE drops it there.
  '10->5': ['t = const INFINITY', ...TAIL],
  '10->6': ['t = const G', ...TAIL],
  '11->4': [
    'p = load_param pt',
    'k1 = const 3', 'm1 = call ecMul p k1',
    `k2 = const ${CURVE_N - 3n}`, 'm2 = call ecMul p k2',
    ...MUL_GATE_ON_P, 't = const INFINITY', ...TAIL,
  ],
  '9->3': [
    'p = load_param pt',
    // `k2` was read only by the rewritten outer ecMul, so it goes with `t_k`.
    'k1 = const 3', 'm1 = call ecMul p k1',
    ...MUL_GATE_ON_P, 't = ref p', ...TAIL,
  ],
};

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

// ---------------------------------------------------------------------------
// Native tier invocation — the same discovery as n104-ec-operand-gate-parity.
// ---------------------------------------------------------------------------

interface Tier {
  id: string;
  binary: string | null;
  cwd: string;
  args: (irPath: string) => string[];
  firstLineOnly?: boolean;
  env?: NodeJS.ProcessEnv;
}

function cargoAwareEnv(): NodeJS.ProcessEnv {
  const home = process.env.HOME ?? '';
  const cargoBin = home ? `${home}/.cargo/bin` : '';
  const currentPath = process.env.PATH ?? '';
  return { ...process.env, PATH: cargoBin ? `${cargoBin}:${currentPath}` : currentPath };
}

function toolchainPresent(probe: string): boolean {
  try {
    execSync(probe, { stdio: 'pipe' });
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

/** Compare without handing vitest two ~1 MB hex strings to diff. */
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
// Tests
// ---------------------------------------------------------------------------

describe('F-115 EC optimizer fixed point: the TS reference shape', () => {
  for (const chain of CHAINS) {
    it(`chain ${chain} is fully reduced`, () => {
      const out = optimizeEC({
        contractName: 'T',
        properties: [],
        methods: [{ name: 'm', params: [], body: probeBody(chain), isPublic: true }],
      });
      expect(out.methods[0]!.body.map(describeBinding)).toEqual(EXPECTED[chain]);
    });
  }
});

describe('F-115 EC optimizer fixed point: cross-tier parity via --ir', () => {
  let tempDir: string;
  const irPaths: Partial<Record<Chain, string>> = {};
  const tsHex: Partial<Record<Chain, string>> = {};

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-f115-'));
    for (const chain of CHAINS) {
      const anf = probeProgram(chain);
      const p = join(tempDir, `${chain.replace('->', '-')}.anf.json`);
      writeFileSync(p, anfToJson(anf));
      irPaths[chain] = p;
      tsHex[chain] = (compileFromANF(anf, { disableConstantFolding: true }).scriptHex as string).toLowerCase();
    }
  });

  afterAll(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  for (const tier of TIERS) {
    describe.skipIf(tier.binary === null)(`${tier.id}`, () => {
      for (const chain of CHAINS) {
        it(`chain ${chain} matches TS`, () => {
          expectSameHex(`ts vs ${tier.id} ${chain}`, tsHex[chain]!, runTier(tier, irPaths[chain]!));
        });
      }
    });
  }
});
