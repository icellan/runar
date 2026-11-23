import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeNewStateAndDataOutputs } from '../../packages/runar-sdk/src/index.js';
import { runStatelessSigned } from '../../packages/runar-testing/src/oracle/real-crypto-execution.js';
import type { ANFProgram } from '../../packages/runar-ir-schema/src/index.js';
import { enforceDriverGate } from './driver-gate.js';

// reverseBytes at its 520-byte bound, in every SDK ANF interpreter.
//
// Since D12 BM-F3 (PR #228) every compiler's reverseBytes ends in
// `OP_0 OP_EQUALVERIFY`: the 520 unrolled peel-one-byte iterations must have
// consumed the whole input, so the script ABORTS on 521+ bytes (it used to
// return the reverse of the first 520 and drop the rest). An interpreter that
// reverses the full input would let an SDK simulation accept a spend the
// network refuses.
//
// Lengths 0 / 1 / 520 are VALUE vectors: inputs/reverse-bytes-{0,1,520}.json,
// with goldens computed independently (Python bytes[::-1]) and checked by
// cross-interpreter.test.ts against every driver and the compiled script.
// This file pins 521: every tier must refuse it — non-zero exit, no result —
// and the compiled script itself must reject it on the real Spend engine, so
// the refusal is checked against the chain and not only tier-vs-tier.

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const DRIVERS_DIR = join(__dirname, 'drivers');
const PROBE = 'conformance/anf-interpreter/programs/reverse-bytes-probe.anf.json';
const REV_SOURCE = 'conformance/closed-findings/RevBytes.runar.ts';

const pattern = (n: number): string =>
  Array.from({ length: n }, (_, i) => ((i * 7 + 0x5a) % 256).toString(16).padStart(2, '0')).join('');
const reverseHex = (h: string): string => (h.match(/../g) ?? []).reverse().join('');
const hexBytes = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, 'hex'));

const OVERSIZE = pattern(521);

/** The probe's `reverseBytes` call binding — where Rust's abort channel fires. */
const probeAnf = JSON.parse(readFileSync(join(REPO_ROOT, PROBE), 'utf8')) as ANFProgram;
const REVERSE_BINDING = probeAnf.methods
  .find((m) => m.name === 'reverse')!
  .body.find((b) => b.value.kind === 'call' && (b.value as { func: string }).func === 'reverseBytes')!.name;

const input521 = {
  anfPath: PROBE,
  methodName: 'reverse',
  currentState: { out: '00' },
  args: { data: OVERSIZE },
  constructorArgs: ['00'],
};

/** The diagnostic every message-carrying tier shares. */
const DIAG = 'reverseBytes: input of 521 bytes exceeds the 520-byte limit';

interface Driver {
  name: string;
  argv: string[];
  present: string;
  /** What the tier's stderr must carry for the refusal. */
  expect: string;
}

const jar = [
  join(DRIVERS_DIR, 'java', 'build', 'libs', 'runar-anf-driver.jar'),
  join(DRIVERS_DIR, 'java', 'build', 'libs', 'java-anf-driver.jar'),
].find(existsSync) ?? join(DRIVERS_DIR, 'java', 'build', 'libs', 'runar-anf-driver.jar');
const rustBin = join(DRIVERS_DIR, 'rust', 'target', 'release', 'runar-anf-driver-rust');
const zigBin = join(DRIVERS_DIR, 'zig', 'zig-out', 'bin', 'runar-anf-driver-zig');

const drivers: Driver[] = [
  { name: 'python', argv: ['python3', join(DRIVERS_DIR, 'python', 'driver.py')], present: join(DRIVERS_DIR, 'python', 'driver.py'), expect: DIAG },
  { name: 'ruby', argv: ['ruby', join(DRIVERS_DIR, 'ruby', 'driver.rb')], present: join(DRIVERS_DIR, 'ruby', 'driver.rb'), expect: DIAG },
  { name: 'go', argv: ['go', 'run', join(DRIVERS_DIR, 'go', 'driver.go')], present: join(DRIVERS_DIR, 'go', 'driver.go'), expect: DIAG },
  // Rust refuses through its abort channel, an AssertionFailureError at the
  // reverseBytes call binding (`byte_builtin_aborts`), as for split/num2bin.
  { name: 'rust', argv: [rustBin], present: rustBin, expect: `binding '${REVERSE_BINDING}'` },
  { name: 'java', argv: ['java', '-jar', jar], present: jar, expect: DIAG },
  // Zig has no message channel: error.ScriptNumberError.
  { name: 'zig', argv: [zigBin], present: zigBin, expect: 'ScriptNumberError' },
];

const isDriverAvailable = (d: { present: string }): boolean => existsSync(d.present);
const missing = drivers.filter((d) => !isDriverAvailable(d));
enforceDriverGate('reverseBytes bound', missing.map((d) => ({ name: d.name, setupHint: 'see drivers/PROTOCOL.md' })), process.env);

const TMP = mkdtempSync(join(tmpdir(), 'reverse-bytes-bound-'));

describe('reverseBytes 520-byte bound: the compiled script (real Spend engine)', () => {
  const rev = readFileSync(join(REPO_ROOT, REV_SOURCE), 'utf8');
  const spend = (data: string, expected: string) =>
    runStatelessSigned({
      source: rev,
      fileName: 'RevBytes.runar.ts',
      method: 'verify',
      args: [hexBytes(data)],
      constructorArgs: { expected },
    });

  it('accepts exactly 520 bytes', () => {
    const r = spend(pattern(520), reverseHex(pattern(520)));
    expect(r.vmError ?? '').toBe('');
    expect(r.vmAccepted).toBe(true);
    expect(r.interpreterAccepted).toBe(true);
  });

  it('rejects 521 bytes against the full reverse (no full-reverse semantics)', () => {
    const r = spend(OVERSIZE, reverseHex(OVERSIZE));
    expect(r.reachedEngine).toBe(true);
    expect(r.vmAccepted).toBe(false);
    // TestContract's interpreter refuses it too.
    expect(r.interpreterAccepted).toBe(false);
  });

  it('rejects 521 bytes against the reverse of the first 520 (no truncation semantics)', () => {
    const r = spend(OVERSIZE, reverseHex(OVERSIZE.slice(0, 1040)));
    expect(r.reachedEngine).toBe(true);
    expect(r.vmAccepted).toBe(false);
  });
});

describe('reverseBytes 520-byte bound (TS SDK reference)', () => {
  it('refuses 521 bytes with the shared diagnostic', () => {
    expect(() =>
      computeNewStateAndDataOutputs(probeAnf, 'reverse', { out: '00' }, { data: OVERSIZE }, ['00']),
    ).toThrow(DIAG);
  });
});

for (const d of drivers) {
  describe.skipIf(!isDriverAvailable(d))(`reverseBytes 520-byte bound (${d.name} SDK)`, () => {
    it('refuses 521 bytes, prints no result', () => {
      const file = join(TMP, `${d.name}-reverse-bytes-521.json`);
      writeFileSync(file, JSON.stringify(input521));
      const res = spawnSync(d.argv[0]!, [...d.argv.slice(1), file], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        timeout: 120_000,
      });
      expect(res.error, `${d.name} could not run`).toBeUndefined();
      expect(res.status, `${d.name} accepted 521 bytes: ${res.stdout}`).not.toBe(0);
      expect(res.stdout.trim(), `${d.name} printed a result for 521 bytes`).toBe('');
      expect(res.stderr).toContain(d.expect);
    }, 120_000);
  });
}
