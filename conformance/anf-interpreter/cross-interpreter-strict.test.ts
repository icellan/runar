import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { executeStrict, AssertionFailureError } from 'runar-sdk';
import type { ANFProgram } from 'runar-ir-schema';

// Strict-mode counterpart to cross-interpreter.test.ts.
//
// Runs the same six fixture inputs through `executeStrict` (TS reference) and
// each per-SDK driver invoked with `--mode=strict`. On a falsy `assert(...)`
// predicate, a strict-mode driver MUST emit:
//
//   { "error": "AssertionFailureError", "methodName": "<m>", "bindingName": "<b>" }
//
// On success it emits the same `{ state, dataOutputs }` envelope as lenient
// mode. The TS reference is stamped first; every per-SDK driver must agree
// byte-for-byte (structural equality — key ordering does not matter).

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const CONFORMANCE_TESTS_DIR = join(__dirname, '../tests');
const INPUTS_DIR = join(__dirname, 'inputs');
const EXPECTED_DIR = join(__dirname, 'expected-strict');
const DRIVERS_DIR = join(__dirname, 'drivers');

const IS_CI = process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true';

interface CaseInput {
  case: string;
  methodName: string;
  currentState: Record<string, unknown>;
  args: Record<string, unknown>;
  constructorArgs: unknown[];
}

interface SuccessOutput {
  state: Record<string, unknown>;
  dataOutputs: Array<{ satoshis: string; script: string }>;
}

interface AssertFailureOutput {
  error: 'AssertionFailureError';
  methodName: string;
  bindingName: string;
}

type CaseOutput = SuccessOutput | AssertFailureOutput;

function isFailureOutput(v: CaseOutput): v is AssertFailureOutput {
  return (v as AssertFailureOutput).error === 'AssertionFailureError';
}

function decodeBigints(v: unknown): unknown {
  if (typeof v === 'string' && /^-?\d+n$/.test(v)) {
    return BigInt(v.slice(0, -1));
  }
  if (Array.isArray(v)) return v.map(decodeBigints);
  if (v && typeof v === 'object') {
    const r: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) r[k] = decodeBigints(val);
    return r;
  }
  return v;
}

function normalizeResult(result: { state: Record<string, unknown>; dataOutputs: Array<{ satoshis: bigint | number; script: string }> }): SuccessOutput {
  function encode(v: unknown): unknown {
    if (typeof v === 'bigint') return v.toString() + 'n';
    if (Array.isArray(v)) return v.map(encode);
    if (v && typeof v === 'object') {
      const r: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v)) r[k] = encode(val);
      return r;
    }
    return v;
  }
  return {
    state: encode(result.state) as Record<string, unknown>,
    dataOutputs: result.dataOutputs.map(d => ({
      satoshis: typeof d.satoshis === 'bigint' ? d.satoshis.toString() + 'n' : String(d.satoshis) + 'n',
      script: d.script,
    })),
  };
}

function loadAnf(caseName: string): ANFProgram {
  const path = join(CONFORMANCE_TESTS_DIR, caseName, 'expected-ir.json');
  return JSON.parse(readFileSync(path, 'utf8')) as ANFProgram;
}

const inputFiles = readdirSync(INPUTS_DIR).filter(f => f.endsWith('.json')).sort();

// ---------------------------------------------------------------------------
// TS SDK reference: imported in-process and stamped against the strict-mode
// goldens. Every per-SDK driver below MUST agree byte-for-byte.
// ---------------------------------------------------------------------------

describe('ANF strict parity (TS SDK)', () => {
  for (const inputFile of inputFiles) {
    const baseName = inputFile.replace(/\.json$/, '');
    it(`${baseName} matches pinned strict golden`, () => {
      const inputRaw = JSON.parse(readFileSync(join(INPUTS_DIR, inputFile), 'utf8')) as CaseInput;
      const input = decodeBigints(inputRaw) as CaseInput;
      const anf = loadAnf(input.case);

      let actual: CaseOutput;
      try {
        const result = executeStrict(
          anf,
          input.methodName,
          input.currentState,
          input.args,
          input.constructorArgs,
        );
        actual = normalizeResult(result);
      } catch (e) {
        if (e instanceof AssertionFailureError) {
          actual = {
            error: 'AssertionFailureError',
            methodName: e.methodName,
            bindingName: e.bindingName,
          };
        } else {
          throw e;
        }
      }

      const expectedPath = join(EXPECTED_DIR, inputFile);
      if (!existsSync(expectedPath)) {
        // Bootstrap mode: first run pins the golden. Subsequent runs assert.
        writeFileSync(expectedPath, JSON.stringify(actual, null, 2) + '\n');
      }
      const expected = JSON.parse(readFileSync(expectedPath, 'utf8')) as CaseOutput;
      expect(actual).toEqual(expected);
    });
  }
});

// ---------------------------------------------------------------------------
// Per-SDK strict driver matrix.
// ---------------------------------------------------------------------------

interface DriverConfig {
  name: string;
  binary: string;
  prefix?: string[];
  setupHint: string;
}

function pythonDriver(): DriverConfig {
  return {
    name: 'python',
    prefix: ['python3'],
    binary: join(DRIVERS_DIR, 'python', 'driver.py'),
    setupHint: 'python3 must be on PATH; driver script lives at drivers/python/driver.py.',
  };
}
function rubyDriver(): DriverConfig {
  return {
    name: 'ruby',
    prefix: ['ruby'],
    binary: join(DRIVERS_DIR, 'ruby', 'driver.rb'),
    setupHint: 'ruby must be on PATH; driver script lives at drivers/ruby/driver.rb.',
  };
}
function goDriver(): DriverConfig {
  return {
    name: 'go',
    prefix: ['go', 'run'],
    binary: join(DRIVERS_DIR, 'go', 'driver.go'),
    setupHint: 'go must be on PATH; driver lives at drivers/go/driver.go.',
  };
}
function rustDriver(): DriverConfig {
  return {
    name: 'rust',
    binary: join(DRIVERS_DIR, 'rust', 'target', 'release', 'runar-anf-driver-rust'),
    setupHint: 'cargo build --release inside drivers/rust/.',
  };
}
function javaDriver(): DriverConfig {
  const jarCandidates = [
    join(DRIVERS_DIR, 'java', 'build', 'libs', 'runar-anf-driver.jar'),
    join(DRIVERS_DIR, 'java', 'build', 'libs', 'java-anf-driver.jar'),
  ];
  const jar = jarCandidates.find(existsSync) ?? jarCandidates[0]!;
  return {
    name: 'java',
    prefix: ['java', '-jar'],
    binary: jar,
    setupHint: 'gradle fatJar --no-daemon inside drivers/java/.',
  };
}
function zigDriver(): DriverConfig {
  return {
    name: 'zig',
    binary: join(DRIVERS_DIR, 'zig', 'zig-out', 'bin', 'runar-anf-driver-zig'),
    setupHint: 'zig build -Doptimize=ReleaseSafe inside drivers/zig/.',
  };
}

const driverConfigs: DriverConfig[] = [
  pythonDriver(),
  rubyDriver(),
  goDriver(),
  rustDriver(),
  javaDriver(),
  zigDriver(),
];

function isDriverAvailable(cfg: DriverConfig): boolean {
  return existsSync(cfg.binary);
}

function runDriver(cfg: DriverConfig, inputFile: string): CaseOutput {
  const argv = cfg.prefix ? [...cfg.prefix, cfg.binary, '--mode=strict', inputFile] : [cfg.binary, '--mode=strict', inputFile];
  const cmd = argv[0]!;
  const args = argv.slice(1);
  const out = execFileSync(cmd, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: REPO_ROOT,
    timeout: 60_000,
    encoding: 'utf8',
  });
  const trimmed = out.trim();
  if (!trimmed) {
    throw new Error(`${cfg.name} strict driver produced empty stdout`);
  }
  return JSON.parse(trimmed) as CaseOutput;
}

const requireAll = IS_CI || process.env.RUNAR_ANF_DRIVERS_STRICT === '1';

const missingDrivers: DriverConfig[] = driverConfigs.filter(c => !isDriverAvailable(c));
if (requireAll && missingDrivers.length > 0) {
  throw new Error(
    `ANF strict-parity drivers missing in CI / strict mode: ${missingDrivers.map(c => c.name).join(', ')}.\n` +
    missingDrivers.map(c => `  - ${c.name}: ${c.setupHint}`).join('\n'),
  );
}

for (const cfg of driverConfigs) {
  describe.skipIf(!isDriverAvailable(cfg))(`ANF strict parity (${cfg.name} SDK)`, () => {
    for (const inputFile of inputFiles) {
      const baseName = inputFile.replace(/\.json$/, '');
      it(`${baseName} matches pinned strict golden`, () => {
        const inputPath = join(INPUTS_DIR, inputFile);
        const actual = runDriver(cfg, inputPath);
        const expectedPath = join(EXPECTED_DIR, inputFile);
        const expected = JSON.parse(readFileSync(expectedPath, 'utf8')) as CaseOutput;
        expect(actual).toEqual(expected);
        // Defensive shape check: failure outputs must always carry both name fields.
        if (isFailureOutput(actual)) {
          expect(actual.methodName.length).toBeGreaterThan(0);
          expect(actual.bindingName.length).toBeGreaterThan(0);
        }
      });
    }
  });
}
