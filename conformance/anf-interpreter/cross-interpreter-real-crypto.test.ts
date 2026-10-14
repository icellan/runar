import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  executeOnChainAuthoritative,
  AssertionFailureError,
} from '../../packages/runar-sdk/src/index.js';
import type { ANFProgram } from '../../packages/runar-ir-schema/src/index.js';
import { enforceDriverGate } from './driver-gate.js';

// Real-crypto counterpart to cross-interpreter.test.ts and
// cross-interpreter-strict.test.ts.
//
// Runs each fixture through `executeOnChainAuthoritative` (TS reference) and
// each per-SDK driver invoked with `--mode=on-chain`. The mode performs:
//
//   - Real ECDSA verify of `checkSig(sig, pk)` against the supplied 32-byte
//     sighash. SEC1 secp256k1 pubkey, DER signature with optional trailing
//     sighash type byte.
//   - Real `checkMultiSig(sigs, pks)` as Spend runs OP_CHECKMULTISIG, with
//     the encoding gates and NULLFAIL (N-259, pinned by
//     ./checkmultisig-onchain.test.ts).
//   - Real `checkPreimage(preimage)`: hash256(preimage) byte-equal to
//     the sighash.
//
// On a falsy `assert(...)` predicate, every driver MUST emit:
//
//   { "error": "AssertionFailureError", "methodName": "<m>", "bindingName": "<b>" }
//
// Where the script itself ABORTS — N-198: a non-empty signature that does not
// verify, which a node rejects under NULLFAIL (BIP146) instead of pushing
// false — each tier signals it through its N-197 opcode-abort channel, which
// this file normalises to one envelope:
//
//   { "error": "ScriptAbort", "methodName": "<m>" }
//
// from: a thrown non-assert Error carrying "OP_CHECKSIG aborts" (TS, and a
// non-zero exit with it on stderr for Go / Python / Ruby / Java); a non-zero
// exit with `ScriptNumberError` on stderr (Zig, which has no message
// channel); or an AssertionFailureError whose binding is the `checkSig` CALL
// rather than an `assert` (Rust).
//
// On success it emits `{ state, dataOutputs, rawOutputs }` — same shape as
// strict + lenient. The TS reference is stamped first; every per-SDK
// driver must agree byte-for-byte (structural equality — key ordering
// does not matter).

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const CONFORMANCE_TESTS_DIR = join(__dirname, '../tests');
const INPUTS_DIR = join(__dirname, 'inputs');
const EXPECTED_DIR = join(__dirname, 'expected-real-crypto');
const DRIVERS_DIR = join(__dirname, 'drivers');

interface CaseInput {
  case: string;
  methodName: string;
  currentState: Record<string, unknown>;
  args: Record<string, unknown>;
  constructorArgs: unknown[];
  sighash: string;
}

interface SuccessOutput {
  state: Record<string, unknown>;
  dataOutputs: Array<{ satoshis: string; script: string }>;
  rawOutputs: Array<{ satoshis: string; script: string }>;
}

interface AssertFailureOutput {
  error: 'AssertionFailureError';
  methodName: string;
  bindingName: string;
}

interface ScriptAbortOutput {
  error: 'ScriptAbort';
  methodName: string;
}

type CaseOutput = SuccessOutput | AssertFailureOutput | ScriptAbortOutput;

function isFailureOutput(v: CaseOutput): v is AssertFailureOutput {
  return (v as AssertFailureOutput).error === 'AssertionFailureError';
}

/** The diagnostic every message-channel tier puts on an OP_CHECKSIG abort. */
const CHECKSIG_ABORT = /OP_CHECKSIG aborts/;

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

function normalizeResult(result: { state: Record<string, unknown>; dataOutputs: Array<{ satoshis: bigint | number; script: string }>; rawOutputs?: Array<{ satoshis: bigint | number; script: string }> }): SuccessOutput {
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

// Only the inputs that carry a `sighash` field — those are the real-crypto
// fixtures. This lets the lenient + strict suites share `inputs/` without
// stepping on the real-crypto fixture inputs.
const inputFiles = readdirSync(INPUTS_DIR)
  .filter(f => f.endsWith('.json'))
  .filter(f => {
    const raw = JSON.parse(readFileSync(join(INPUTS_DIR, f), 'utf8'));
    return typeof raw.sighash === 'string';
  })
  .sort();

// ---------------------------------------------------------------------------
// TS SDK reference: imported in-process and stamped against the on-chain
// goldens. Every per-SDK driver below MUST agree byte-for-byte.
// ---------------------------------------------------------------------------

describe('ANF real-crypto parity (TS SDK)', () => {
  // Non-vacuity sentinel: an empty or fully-filtered corpus generates zero
  // cases, and every describe in this file would still report green. This is
  // the thinnest of the three corpora, so it is the likeliest to reach zero.
  it('discovers the real-crypto input corpus', () => {
    expect(inputFiles.length).toBeGreaterThan(0);
  });

  for (const inputFile of inputFiles) {
    const baseName = inputFile.replace(/\.json$/, '');
    it(`${baseName} matches pinned real-crypto golden`, () => {
      const inputRaw = JSON.parse(readFileSync(join(INPUTS_DIR, inputFile), 'utf8')) as CaseInput;
      const input = decodeBigints(inputRaw) as CaseInput;
      const anf = loadAnf(input.case);

      let actual: CaseOutput;
      try {
        const result = executeOnChainAuthoritative(
          anf,
          input.methodName,
          input.currentState,
          input.args,
          input.constructorArgs,
          { sighash: input.sighash },
        );
        actual = normalizeResult(result);
      } catch (e) {
        if (e instanceof AssertionFailureError) {
          actual = {
            error: 'AssertionFailureError',
            methodName: e.methodName,
            bindingName: e.bindingName,
          };
        } else if (e instanceof Error && CHECKSIG_ABORT.test(e.message)) {
          actual = { error: 'ScriptAbort', methodName: input.methodName };
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
// Per-SDK real-crypto driver matrix.
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
  const argv = cfg.prefix ? [...cfg.prefix, cfg.binary, '--mode=on-chain', inputFile] : [cfg.binary, '--mode=on-chain', inputFile];
  const cmd = argv[0]!;
  const args = argv.slice(1);
  const r = spawnSync(cmd, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: REPO_ROOT,
    timeout: 60_000,
    encoding: 'utf8',
  });
  const input = JSON.parse(readFileSync(inputFile, 'utf8')) as CaseInput;
  const stderr = r.stderr ?? '';
  if (r.status !== 0) {
    // An opcode abort (see the header). Anything else is a real driver error.
    const aborted = cfg.name === 'zig' ? /ScriptNumberError/.test(stderr) : CHECKSIG_ABORT.test(stderr);
    if (aborted && (r.stdout ?? '').trim() === '') {
      return { error: 'ScriptAbort', methodName: input.methodName };
    }
    throw new Error(`${cfg.name} on-chain driver exited ${r.status}: ${stderr}`);
  }
  const trimmed = (r.stdout ?? '').trim();
  if (!trimmed) {
    throw new Error(`${cfg.name} on-chain driver produced empty stdout`);
  }
  const out = JSON.parse(trimmed) as CaseOutput;
  // Rust's opcode-abort channel is an AssertionFailureError at the aborting
  // CALL binding; an `assert` binding there is a genuine assert failure.
  if (cfg.name === 'rust' && isFailureOutput(out)) {
    const method = loadAnf(input.case).methods.find(m => m.name === out.methodName);
    const binding = method?.body.find(b => b.name === out.bindingName);
    if (binding?.value.kind === 'call' && binding.value.func === 'checkSig') {
      return { error: 'ScriptAbort', methodName: out.methodName };
    }
  }
  return out;
}

const missingDrivers: DriverConfig[] = driverConfigs.filter(c => !isDriverAvailable(c));
enforceDriverGate('ANF real-crypto-parity', missingDrivers, process.env);

for (const cfg of driverConfigs) {
  describe.skipIf(!isDriverAvailable(cfg))(`ANF real-crypto parity (${cfg.name} SDK)`, () => {
    for (const inputFile of inputFiles) {
      const baseName = inputFile.replace(/\.json$/, '');
      it(`${baseName} matches pinned real-crypto golden`, () => {
        const inputPath = join(INPUTS_DIR, inputFile);
        const actual = runDriver(cfg, inputPath);
        const expectedPath = join(EXPECTED_DIR, inputFile);
        const expected = JSON.parse(readFileSync(expectedPath, 'utf8')) as CaseOutput;
        expect(actual).toEqual(expected);
        if (isFailureOutput(actual)) {
          expect(actual.methodName.length).toBeGreaterThan(0);
          expect(actual.bindingName.length).toBeGreaterThan(0);
        }
      });
    }
  });
}
