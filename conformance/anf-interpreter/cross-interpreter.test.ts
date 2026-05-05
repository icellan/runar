import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeNewStateAndDataOutputs } from 'runar-sdk';
import type { ANFProgram } from 'runar-ir-schema';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const CONFORMANCE_TESTS_DIR = join(__dirname, '../tests');
const INPUTS_DIR = join(__dirname, 'inputs');
const EXPECTED_DIR = join(__dirname, 'expected');
const DRIVERS_DIR = join(__dirname, 'drivers');

const IS_CI = process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true';

interface CaseInput {
  case: string;
  methodName: string;
  currentState: Record<string, unknown>;
  args: Record<string, unknown>;
  constructorArgs: unknown[];
}

interface CaseOutput {
  state: Record<string, unknown>;
  dataOutputs: Array<{ satoshis: string; script: string }>;
  rawOutputs: Array<{ satoshis: string; script: string }>;
}

/**
 * Decode `"42n"` → `42n` recursively. Inputs use the trailing-`n` convention
 * for bigints to keep them representable in JSON.
 */
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

/** Normalize the interpreter result so `bigint`s are stringly-comparable. */
function normalizeResult(result: { state: Record<string, unknown>; dataOutputs: Array<{ satoshis: bigint | number; script: string }>; rawOutputs?: Array<{ satoshis: bigint | number; script: string }> }): CaseOutput {
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
  const encodeOutput = (d: { satoshis: bigint | number; script: string }) => ({
    satoshis: typeof d.satoshis === 'bigint' ? d.satoshis.toString() + 'n' : String(d.satoshis) + 'n',
    script: d.script,
  });
  return {
    state: encode(result.state) as Record<string, unknown>,
    dataOutputs: result.dataOutputs.map(encodeOutput),
    rawOutputs: (result.rawOutputs ?? []).map(encodeOutput),
  };
}

function loadAnf(caseName: string): ANFProgram {
  const path = join(CONFORMANCE_TESTS_DIR, caseName, 'expected-ir.json');
  return JSON.parse(readFileSync(path, 'utf8')) as ANFProgram;
}

const inputFiles = readdirSync(INPUTS_DIR).filter(f => f.endsWith('.json')).sort();

// ---------------------------------------------------------------------------
// TS SDK reference: imported in-process so the goldens are stamped against
// the canonical implementation. Every per-language driver below MUST agree
// with these goldens byte-for-byte.
// ---------------------------------------------------------------------------

describe('ANF interpreter parity (TS SDK)', () => {
  for (const inputFile of inputFiles) {
    const baseName = inputFile.replace(/\.json$/, '');
    it(`${baseName} matches pinned golden`, () => {
      const inputRaw = JSON.parse(readFileSync(join(INPUTS_DIR, inputFile), 'utf8')) as CaseInput;
      const input = decodeBigints(inputRaw) as CaseInput;
      const anf = loadAnf(input.case);
      const result = computeNewStateAndDataOutputs(
        anf,
        input.methodName,
        input.currentState,
        input.args,
        input.constructorArgs,
      );
      const actual = normalizeResult(result);

      const expectedPath = join(EXPECTED_DIR, inputFile);
      if (!existsSync(expectedPath)) {
        // Bootstrap mode: first run pins the golden. Subsequent runs assert.
        writeFileSync(expectedPath, JSON.stringify(actual, null, 2) + '\n');
        // Re-read so the assertion below still runs against the freshly written
        // file — this both creates the golden and proves it can round-trip.
      }
      const expected = JSON.parse(readFileSync(expectedPath, 'utf8')) as CaseOutput;
      expect(actual).toEqual(expected);
    });
  }
});

// ---------------------------------------------------------------------------
// Per-SDK driver matrix.
//
// Every SDK with an ANF interpreter implementation ships a small CLI driver
// under `conformance/anf-interpreter/drivers/<lang>/` that conforms to the
// protocol spec at `drivers/PROTOCOL.md`. The test below spawns each driver
// for every input fixture and asserts the output equals the TS-pinned golden.
//
// CI policy: when CI=true, missing drivers/binaries hard-fail the suite.
// Local devs without a given toolchain see a single warning and skip the
// per-language describe block (matches the cross-compiler.test.ts gate).
// Set RUNAR_ANF_DRIVERS_STRICT=1 to upgrade to hard-fail locally too.
// ---------------------------------------------------------------------------

interface DriverConfig {
  /** Display name, used in test labels and missing-driver diagnostics. */
  name: string;
  /** Absolute path to the driver binary or script. */
  binary: string;
  /** Argv prefix (e.g. ['node'] for a JS runner, ['ruby'] for a script). */
  prefix?: string[];
  /** Setup hint shown when the driver/binary isn't built. */
  setupHint: string;
}

function pythonDriver(): DriverConfig {
  return {
    name: 'python',
    prefix: ['python3'],
    binary: join(DRIVERS_DIR, 'python', 'driver.py'),
    setupHint: 'python3 must be on PATH; driver script lives at drivers/python/driver.py and imports the Python SDK from packages/runar-py.',
  };
}

function rubyDriver(): DriverConfig {
  return {
    name: 'ruby',
    prefix: ['ruby'],
    binary: join(DRIVERS_DIR, 'ruby', 'driver.rb'),
    setupHint: 'ruby must be on PATH; driver script lives at drivers/ruby/driver.rb and requires the Ruby SDK from packages/runar-rb/lib.',
  };
}

function goDriver(): DriverConfig {
  // The Go driver is a `go run`-able single-file program. We run it via
  // `go run` so a one-time build isn't required; this matches the existing
  // sdk-output go-sdk-tool pattern.
  return {
    name: 'go',
    prefix: ['go', 'run'],
    binary: join(DRIVERS_DIR, 'go', 'driver.go'),
    setupHint: 'go must be on PATH; driver lives at drivers/go/driver.go and depends on the Go SDK via go.work.',
  };
}

function rustDriver(): DriverConfig {
  return {
    name: 'rust',
    binary: join(DRIVERS_DIR, 'rust', 'target', 'release', 'runar-anf-driver-rust'),
    setupHint: 'cargo build --release inside drivers/rust/ to produce target/release/runar-anf-driver-rust.',
  };
}

function javaDriver(): DriverConfig {
  // Driver builds a fat-jar at build/libs/runar-anf-driver.jar.
  const jarCandidates = [
    join(DRIVERS_DIR, 'java', 'build', 'libs', 'runar-anf-driver.jar'),
    join(DRIVERS_DIR, 'java', 'build', 'libs', 'java-anf-driver.jar'),
  ];
  const jar = jarCandidates.find(existsSync) ?? jarCandidates[0]!;
  return {
    name: 'java',
    prefix: ['java', '-jar'],
    binary: jar,
    setupHint: 'gradle fatJar --no-daemon inside drivers/java/ to build the driver fat-jar.',
  };
}

function zigDriver(): DriverConfig {
  return {
    name: 'zig',
    binary: join(DRIVERS_DIR, 'zig', 'zig-out', 'bin', 'runar-anf-driver-zig'),
    setupHint: 'zig build -Doptimize=ReleaseSafe inside drivers/zig/ to produce zig-out/bin/runar-anf-driver-zig.',
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
  // For drivers invoked through a runtime (python3, ruby, go run, java -jar),
  // existence of the script/jar/source is the build-state proof. For native
  // binaries (rust, zig), the binary itself must exist.
  return existsSync(cfg.binary);
}

function runDriver(cfg: DriverConfig, inputFile: string): CaseOutput {
  const argv = cfg.prefix ? [...cfg.prefix, cfg.binary, inputFile] : [cfg.binary, inputFile];
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
    throw new Error(`${cfg.name} driver produced empty stdout`);
  }
  return JSON.parse(trimmed) as CaseOutput;
}

const requireAll = IS_CI || process.env.RUNAR_ANF_DRIVERS_STRICT === '1';

const missingDrivers: DriverConfig[] = driverConfigs.filter(c => !isDriverAvailable(c));
if (requireAll && missingDrivers.length > 0) {
  throw new Error(
    `ANF parity drivers missing in CI / strict mode: ${missingDrivers.map(c => c.name).join(', ')}.\n` +
    missingDrivers.map(c => `  - ${c.name}: ${c.setupHint}`).join('\n'),
  );
}

for (const cfg of driverConfigs) {
  describe.skipIf(!isDriverAvailable(cfg))(`ANF interpreter parity (${cfg.name} SDK)`, () => {
    for (const inputFile of inputFiles) {
      const baseName = inputFile.replace(/\.json$/, '');
      it(`${baseName} matches pinned golden`, () => {
        const inputPath = join(INPUTS_DIR, inputFile);
        const actual = runDriver(cfg, inputPath);
        const expectedPath = join(EXPECTED_DIR, inputFile);
        const expected = JSON.parse(readFileSync(expectedPath, 'utf8')) as CaseOutput;
        expect(actual).toEqual(expected);
      });
    }
  });
}
