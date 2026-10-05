/**
 * N-104 — the EC identity rewrites keep the replaced builtin's operand gate,
 * identically in every tier.
 *
 *     ec-add-identity-right   ecAdd($x, INFINITY) -> $x   + ecAdd's gate on $x
 *     ec-add-identity-left    ecAdd(INFINITY, $x) -> $x   + ecAdd's gate on $x
 *     ec-mul-one              ecMul($x, 1)        -> $x   + ecMul's gate on $x
 *     ec-mul-zero             ecMul($x, 0)        -> INFINITY + ecMul's gate on $x
 *
 * The gate is declared in optimizer/ec-rules.json ("gate") and spelled out in
 * `emitAddOperandGate` / `emitMulOperandGate` (optimizer/anf-ec.ts). This file
 * pins (1) the exact ANF the TS reference emits — names, kinds, operands,
 * order — which every tier's own N-104 test pins too, (2) that the JSON
 * declares a gate on exactly these four rules, and (3) that every native tier
 * compiles the same probe ANF (via `--ir`) to the same script as TS.
 *
 * WHAT IT DOES NOT PROVE: what the gate does at runtime. That is executed on
 * the real Spend engine, against both optimizer modes, by
 * packages/runar-testing/src/__tests__/n104-ec-optimizer-operand-gate.test.ts.
 * Only ec-mul-one is reachable from a conformance fixture (ec-demo,
 * ec-primitives), so (3) is the only cross-tier check the other three get.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, execSync } from 'child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { tmpdir } from 'os';
import { compileFromANF } from '../index.js';
import { optimizeEC } from '../optimizer/anf-ec.js';
import type { ANFProgram, ANFBinding, ANFValue } from '../ir/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..', '..');

const INFINITY_HEX = '0'.repeat(128);
const FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;

function b(name: string, value: ANFValue): ANFBinding {
  return { name, value };
}

function constructorMethod() {
  // Byte-for-byte the shape pass 04 emits for `constructor(tag) { super(tag); this.tag = tag; }`
  // — hand-rolling a different spelling makes the native `--ir` loaders reject
  // the file and the whole test skip for the wrong reason.
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

type Rule = 'ec-add-identity-right' | 'ec-add-identity-left' | 'ec-mul-one' | 'ec-mul-zero';
const RULES: Rule[] = ['ec-add-identity-right', 'ec-add-identity-left', 'ec-mul-one', 'ec-mul-zero'];

/** `t = <rule's call>` over the load_param `p`, then `assert(t)`. */
function probeBody(rule: Rule): ANFBinding[] {
  const second: Record<Rule, ANFBinding> = {
    'ec-add-identity-right': b('inf', { kind: 'load_const', value: INFINITY_HEX }),
    'ec-add-identity-left': b('inf', { kind: 'load_const', value: INFINITY_HEX }),
    'ec-mul-one': b('one', { kind: 'load_const', value: 1n }),
    'ec-mul-zero': b('zero', { kind: 'load_const', value: 0n }),
  };
  const call: Record<Rule, ANFValue> = {
    'ec-add-identity-right': { kind: 'call', func: 'ecAdd', args: ['p', 'inf'] },
    'ec-add-identity-left': { kind: 'call', func: 'ecAdd', args: ['inf', 'p'] },
    'ec-mul-one': { kind: 'call', func: 'ecMul', args: ['p', 'one'] },
    'ec-mul-zero': { kind: 'call', func: 'ecMul', args: ['p', 'zero'] },
  };
  return [
    b('p', { kind: 'load_param', name: 'pt' }),
    second[rule],
    b('t', call[rule]),
    b('a', { kind: 'assert', value: 't' }),
  ];
}

function probeProgram(rule: Rule): ANFProgram {
  return {
    contractName: 'ECOperandGate',
    properties: [{ name: 'tag', type: 'bigint', readonly: true }],
    methods: [
      constructorMethod(),
      { name: 'spend', params: [{ name: 'pt', type: 'Point' }], body: probeBody(rule), isPublic: true },
    ],
  };
}

function describeBinding(x: ANFBinding): string {
  const v = x.value;
  let d: string;
  switch (v.kind) {
    case 'load_param': d = `load_param ${v.name}`; break;
    case 'load_const':
      if (v.value === INFINITY_HEX) d = 'const INFINITY';
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

const ADD_GATE = [
  't_px = call ecPointX p',
  't_py = call ecPointY p',
  `t_fp = const ${FIELD_P}`,
  't_pxok = bin_op < t_px t_fp',
  't_pyok = bin_op < t_py t_fp',
  't_ok = bin_op && t_pxok t_pyok',
  't_gate = assert t_ok',
];
const MUL_GATE = [
  't_inf = const INFINITY',
  't_isinf = bin_op === p t_inf bytes',
  't_oncurve = call ecOnCurve p',
  't_ok = bin_op || t_isinf t_oncurve',
  't_gate = assert t_ok',
];
const EXPECTED: Record<Rule, string[]> = {
  'ec-add-identity-right': ['p = load_param pt', ...ADD_GATE, 't = ref p', 'a = assert t'],
  'ec-add-identity-left': ['p = load_param pt', ...ADD_GATE, 't = ref p', 'a = assert t'],
  'ec-mul-one': ['p = load_param pt', ...MUL_GATE, 't = ref p', 'a = assert t'],
  'ec-mul-zero': ['p = load_param pt', ...MUL_GATE, 't = const INFINITY', 'a = assert t'],
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
// Native tier invocation
// ---------------------------------------------------------------------------

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

// Binary discovery. `conformance/runner/runner.ts` is the project's source of
// truth for this (findGoBinary / findRustBinary / ...), but importing it from a
// packages/ test drags in conformance's standalone npm install and makes the
// TS toolchain emit compiled .js next to the runner. These are the same
// candidate paths, reduced to what an `--ir --hex` invocation needs. A tier
// whose toolchain is absent returns null and its two tests skip.

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
// Tests
// ---------------------------------------------------------------------------

describe('N-104 operand gate: the TS reference shape', () => {
  for (const rule of RULES) {
    it(`${rule} emits the gate ahead of the rewritten binding`, () => {
      const out = optimizeEC({ contractName: 'T', properties: [], methods: [{ name: 'm', params: [], body: probeBody(rule), isPublic: true }] });
      expect(out.methods[0]!.body.map(describeBinding)).toEqual(EXPECTED[rule]);
    });
  }

  it('optimizer/ec-rules.json declares a gate on exactly these four rules', () => {
    const rules = JSON.parse(readFileSync(join(REPO_ROOT, 'optimizer', 'ec-rules.json'), 'utf-8')) as Array<{
      name: string; gate?: { of: string; operand: string };
    }>;
    const gated = Object.fromEntries(rules.filter((r) => r.gate).map((r) => [r.name, r.gate]));
    expect(gated).toEqual({
      'ec-add-identity-right': { of: 'ecAdd', operand: '$x' },
      'ec-add-identity-left': { of: 'ecAdd', operand: '$x' },
      'ec-mul-one': { of: 'ecMul', operand: '$x' },
      'ec-mul-zero': { of: 'ecMul', operand: '$x' },
    });
  });
});

describe('N-104 operand gate: cross-tier parity via --ir', () => {
  let tempDir: string;
  const irPaths: Partial<Record<Rule, string>> = {};
  const tsHex: Partial<Record<Rule, string>> = {};

  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'runar-n104-'));
    for (const rule of RULES) {
      const anf = probeProgram(rule);
      const p = join(tempDir, `${rule}.anf.json`);
      writeFileSync(p, anfToJson(anf));
      irPaths[rule] = p;
      tsHex[rule] = (compileFromANF(anf, { disableConstantFolding: true }).scriptHex as string).toLowerCase();
    }
  });

  afterAll(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('the rewrite still elides the builtin: each TS script is under 1 KB', () => {
    for (const rule of RULES) expect(tsHex[rule]!.length / 2, rule).toBeLessThan(1024);
  });

  for (const tier of TIERS) {
    describe.skipIf(tier.binary === null)(`${tier.id}`, () => {
      for (const rule of RULES) {
        it(`${rule} matches TS`, () => {
          expectSameHex(`ts vs ${tier.id} ${rule}`, tsHex[rule]!, runTier(tier, irPaths[rule]!));
        });
      }
    });
  }
});
