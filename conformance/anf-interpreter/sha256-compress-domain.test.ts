import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeNewStateAndDataOutputs } from '../../packages/runar-sdk/src/index.js';
import type { ANFProgram } from '../../packages/runar-ir-schema/src/index.js';
import { enforceDriverGate } from './driver-gate.js';

// D16 — sha256Compress in every SDK ANF interpreter, over the real-crypto
// witness rows (conformance/witnesses/real-crypto/sha256-compress.json, whose
// verdicts are pinned against the compiled script on the @bsv/sdk Spend).
//
// Each witness row is replayed through every interpreter on the
// Sha256CompressProbe program (programs/), which routes the compressed state
// into a state field so lenient mode can observe it:
//  - a row the script refuses for the input's SIZE — a state that is not 32
//    bytes or a block that is not 64 bytes (F-114, incl. the 63-byte prefix
//    of a zero-tail block that used to hash like the 64-byte block) — must
//    fail closed, never a digest, with the shared diagnostic. Zig refuses
//    through error.ScriptNumberError (no message channel); every other tier
//    carries the diagnostic text.
//  - every other row must produce a digest, equal to the row's expected
//    digest exactly when the script accepts the row.
// More value vectors (a chained second block, an arbitrary non-IV state) live
// in ./inputs/sha256-compress-*.json, checked by cross-interpreter.test.ts
// against independently computed goldens and the compiled script.

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const DRIVERS_DIR = join(__dirname, 'drivers');
const PROBE = 'conformance/anf-interpreter/programs/sha256-compress-probe.anf.json';

interface WitnessSpend {
  method: string;
  args: [string, string];
  expect: 'accept' | 'reject';
  /** A row-level override of the fixture's constructor args. */
  constructorArgs?: { expected: string };
}
const witness = JSON.parse(
  readFileSync(join(REPO_ROOT, 'conformance/witnesses/real-crypto/sha256-compress.json'), 'utf8'),
) as { constructorArgs: { expected: string }; spends: WitnessSpend[] };

interface Vector {
  name: string;
  input: {
    anfPath: string;
    methodName: string;
    currentState: Record<string, unknown>;
    args: Record<string, unknown>;
    constructorArgs: unknown[];
  };
  /** The shared diagnostic for a domain refusal; null when a digest is due. */
  error: string | null;
  /** The script's verdict on the row. */
  accept: boolean;
  /** The digest the script compares against on this row. */
  expected: string;
}

/** The diagnostic the compiled script's size checks correspond to (F-114), or null. */
function domainError(stateHex: string, blockHex: string): string | null {
  if (stateHex.length / 2 !== 32) return `sha256Compress: state must be 32 bytes, got ${stateHex.length / 2}`;
  if (blockHex.length / 2 !== 64) return `sha256Compress: block must be 64 bytes, got ${blockHex.length / 2}`;
  return null;
}

const vectors: Vector[] = witness.spends.map((s, i) => {
  const [state, block] = s.args;
  return {
    name: `witness-row-${i}-${s.expect}`,
    input: {
      anfPath: PROBE,
      methodName: 'compress',
      currentState: { digest: '00' },
      args: { state, block },
      constructorArgs: ['00'],
    },
    error: domainError(state, block),
    accept: s.expect === 'accept',
    expected: (s.constructorArgs ?? witness.constructorArgs).expected,
  };
});

const decode = (v: unknown): unknown => {
  if (typeof v === 'string' && /^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
  if (Array.isArray(v)) return v.map(decode);
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, decode(x)]));
  }
  return v;
};

interface Driver {
  name: string;
  argv: string[];
  /** What the tier's stderr must carry for a refusal. */
  expect: (v: Vector) => string;
}

const jar = [
  join(DRIVERS_DIR, 'java', 'build', 'libs', 'runar-anf-driver.jar'),
  join(DRIVERS_DIR, 'java', 'build', 'libs', 'java-anf-driver.jar'),
].find(existsSync) ?? join(DRIVERS_DIR, 'java', 'build', 'libs', 'runar-anf-driver.jar');

const drivers: Array<Driver & { present: string }> = [
  { name: 'python', argv: ['python3', join(DRIVERS_DIR, 'python', 'driver.py')], present: join(DRIVERS_DIR, 'python', 'driver.py'), expect: (v) => v.error! },
  { name: 'ruby', argv: ['ruby', join(DRIVERS_DIR, 'ruby', 'driver.rb')], present: join(DRIVERS_DIR, 'ruby', 'driver.rb'), expect: (v) => v.error! },
  { name: 'go', argv: ['go', 'run', join(DRIVERS_DIR, 'go', 'driver.go')], present: join(DRIVERS_DIR, 'go', 'driver.go'), expect: (v) => v.error! },
  {
    name: 'rust',
    argv: [join(DRIVERS_DIR, 'rust', 'target', 'release', 'runar-anf-driver-rust')],
    present: join(DRIVERS_DIR, 'rust', 'target', 'release', 'runar-anf-driver-rust'),
    expect: (v) => v.error!,
  },
  { name: 'java', argv: ['java', '-jar', jar], present: jar, expect: (v) => v.error! },
  {
    name: 'zig',
    argv: [join(DRIVERS_DIR, 'zig', 'zig-out', 'bin', 'runar-anf-driver-zig')],
    present: join(DRIVERS_DIR, 'zig', 'zig-out', 'bin', 'runar-anf-driver-zig'),
    expect: () => 'ScriptNumberError',
  },
];

/** Build-state proof, as cross-interpreter.test.ts's isDriverAvailable. */
const isDriverAvailable = (d: { present: string }): boolean => existsSync(d.present);

const missing = drivers.filter((d) => !isDriverAvailable(d));
enforceDriverGate('sha256Compress domain', missing.map((d) => ({ name: d.name, setupHint: 'see drivers/PROTOCOL.md' })), process.env);

const TMP = mkdtempSync(join(tmpdir(), 'sha256-compress-domain-'));

function runTs(v: Vector): unknown {
  const anf = JSON.parse(readFileSync(join(REPO_ROOT, v.input.anfPath), 'utf8')) as ANFProgram;
  return computeNewStateAndDataOutputs(
    anf,
    v.input.methodName,
    decode(v.input.currentState) as Record<string, unknown>,
    decode(v.input.args) as Record<string, unknown>,
    decode(v.input.constructorArgs) as unknown[],
  ).state.digest;
}

describe('D16: sha256Compress over the witness rows (TS SDK reference)', () => {
  it('replays every witness row: the accepts and the F-114 state / block size refusals', () => {
    expect(vectors.filter((v) => v.accept).length).toBeGreaterThanOrEqual(2);
    expect(vectors.filter((v) => v.error?.includes('state must be')).length).toBeGreaterThanOrEqual(2);
    expect(vectors.filter((v) => v.error?.includes('block must be')).length).toBeGreaterThanOrEqual(2);
    // Every row the script refuses is a size refusal; none is accepted with a bad size.
    for (const v of vectors) expect(v.accept, v.name).toBe(v.error === null);
  });
  for (const v of vectors) {
    if (v.error !== null) {
      it(`${v.name}: throws the shared diagnostic`, () => {
        expect(() => runTs(v)).toThrow(v.error!);
      });
    } else {
      it(`${v.name}: digest ${v.accept ? 'equals' : 'differs from'} the fixture's expected`, () => {
        const digest = runTs(v);
        if (v.accept) expect(digest).toBe(v.expected);
        else expect(digest).not.toBe(v.expected);
        expect(digest).toMatch(/^[0-9a-f]{64}$/);
      });
    }
  }
});

for (const d of drivers) {
  describe.skipIf(!isDriverAvailable(d))(`D16: sha256Compress over the witness rows (${d.name} SDK)`, () => {
    for (const v of vectors) {
      it(`${v.name}: ${v.error === null ? 'digest' : 'refused, no digest'}`, () => {
        const file = join(TMP, `${d.name}-${v.name}.json`);
        writeFileSync(file, JSON.stringify(v.input));
        const res = spawnSync(d.argv[0]!, [...d.argv.slice(1), file], {
          cwd: REPO_ROOT,
          encoding: 'utf8',
          timeout: 120_000,
        });
        expect(res.error, `${d.name} could not run`).toBeUndefined();
        if (v.error !== null) {
          expect(res.status, `${d.name} accepted ${v.name}: ${res.stdout}`).not.toBe(0);
          expect(res.stdout.trim(), `${d.name} printed a result for ${v.name}`).toBe('');
          expect(res.stderr).toContain(d.expect(v));
        } else {
          expect(res.status, `${d.name} failed ${v.name}: ${res.stderr}`).toBe(0);
          const digest = (JSON.parse(res.stdout) as { state: { digest: string } }).state.digest;
          expect(digest).toBe(runTs(v));
          if (v.accept) expect(digest).toBe(v.expected);
        }
      }, 120_000);
    }
  });
}
