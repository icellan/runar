import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeNewStateAndDataOutputs } from '../../packages/runar-sdk/src/index.js';
import type { ANFProgram } from '../../packages/runar-ir-schema/src/index.js';
import { enforceDriverGate } from './driver-gate.js';

// D11 — sha256Finalize in every SDK ANF interpreter, over the real-crypto
// witness rows (conformance/witnesses/real-crypto/sha256-finalize.json, whose
// verdicts are pinned against the compiled script on the @bsv/sdk Spend).
//
// Each witness row is replayed through every interpreter on the
// Sha256FinalizeProbe program (programs/), which routes the digest into a
// state field so lenient mode can observe it:
//  - a row the script refuses for the input's DOMAIN — msgBitLen outside
//    [0, 2^64) (GK-BUG-013, incl. the 2^64 + 24 alias that hashed like 24), a
//    state that is not 32 bytes (F-114), more than 119 remaining bytes
//    (F-142) — must fail closed, never a digest, with the shared diagnostic.
//    Zig refuses through error.ScriptNumberError (no message channel); every
//    other tier carries the diagnostic text.
//  - every other row must produce a digest, equal to the fixture's expected
//    SHA-256('abc') exactly when the script accepts the row.
// More value vectors (two blocks, after a sha256Compress, msgBitLen in
// [2^63, 2^64)) live in ./inputs/sha256-finalize-*.json, checked by
// cross-interpreter.test.ts against independently computed goldens and the
// compiled script.
//
// sha256Compress (D16) has its own witness replay: sha256-compress-domain.test.ts.

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const DRIVERS_DIR = join(__dirname, 'drivers');
const PROBE = 'conformance/anf-interpreter/programs/sha256-finalize-probe.anf.json';

interface WitnessSpend {
  method: string;
  args: [string, string, string];
  expect: 'accept' | 'reject';
}
const witness = JSON.parse(
  readFileSync(join(REPO_ROOT, 'conformance/witnesses/real-crypto/sha256-finalize.json'), 'utf8'),
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
}

/** The diagnostic the compiled script's domain checks correspond to, or null. */
function domainError(stateHex: string, remainingHex: string, bitLen: bigint): string | null {
  if (stateHex.length / 2 !== 32) return `sha256Finalize: state must be 32 bytes, got ${stateHex.length / 2}`;
  if (remainingHex.length / 2 > 119) {
    return `sha256Finalize: remaining must be 0-119 bytes, got ${remainingHex.length / 2}`;
  }
  if (bitLen < 0n || bitLen >= 1n << 64n) return `sha256Finalize: msgBitLen must be in [0, 2^64), got ${bitLen}`;
  return null;
}

const vectors: Vector[] = witness.spends.map((s, i) => {
  const [state, remaining, bitLenText] = s.args;
  const bitLen = BigInt(bitLenText.slice(0, -1));
  return {
    name: `witness-row-${i}-${s.expect}`,
    input: {
      anfPath: PROBE,
      methodName: 'finalize',
      currentState: { digest: '00' },
      args: { state, remaining, msgBitLen: bitLenText },
      constructorArgs: ['00'],
    },
    error: domainError(state, remaining, bitLen),
    accept: s.expect === 'accept',
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
enforceDriverGate('sha256Finalize domain', missing.map((d) => ({ name: d.name, setupHint: 'see drivers/PROTOCOL.md' })), process.env);

const TMP = mkdtempSync(join(tmpdir(), 'sha256-finalize-domain-'));

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

describe('D11: sha256Finalize over the witness rows (TS SDK reference)', () => {
  it('replays every witness row: one accept, the GK-BUG-013 / F-114 / F-142 domain refusals, a digest mismatch', () => {
    expect(vectors.filter((v) => v.accept)).toHaveLength(1);
    expect(vectors.filter((v) => v.error?.includes('msgBitLen')).length).toBeGreaterThanOrEqual(2);
    expect(vectors.filter((v) => v.error?.includes('state must be')).length).toBeGreaterThanOrEqual(1);
    expect(vectors.filter((v) => v.error?.includes('remaining must be')).length).toBeGreaterThanOrEqual(1);
    expect(vectors.filter((v) => !v.accept && v.error === null).length).toBeGreaterThanOrEqual(1);
  });
  for (const v of vectors) {
    if (v.error !== null) {
      it(`${v.name}: throws the shared diagnostic`, () => {
        expect(() => runTs(v)).toThrow(v.error!);
      });
    } else {
      it(`${v.name}: digest ${v.accept ? 'equals' : 'differs from'} the fixture's expected`, () => {
        const digest = runTs(v);
        if (v.accept) expect(digest).toBe(witness.constructorArgs.expected);
        else expect(digest).not.toBe(witness.constructorArgs.expected);
        expect(digest).toMatch(/^[0-9a-f]{64}$/);
      });
    }
  }
});

for (const d of drivers) {
  describe.skipIf(!isDriverAvailable(d))(`D11: sha256Finalize over the witness rows (${d.name} SDK)`, () => {
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
          if (v.accept) expect(digest).toBe(witness.constructorArgs.expected);
        }
      }, 120_000);
    }
  });
}
