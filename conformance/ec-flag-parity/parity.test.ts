/**
 * The flag-parity fixture is DERIVED, and must never go stale.
 *
 * `expected.json` is the target every non-TypeScript tier's port is measured
 * against. If a deliberate TS codegen change moves the bytes and nobody
 * regenerates the file, six tiers keep passing against a pin that no longer
 * describes the reference — the fixture would then be certifying agreement with
 * a compiler that no longer exists. So re-derive it here and require equality.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — plain ESM helper, shared with the npm generate script.
import { buildParity, VARIANTS } from '../scripts/gen-ec-flag-parity.mjs';

const expectedPath = join(__dirname, 'expected.json');

describe('ec-flag-parity/expected.json', () => {
  const checkedIn = JSON.parse(readFileSync(expectedPath, 'utf8'));
  const derived = buildParity();

  it('matches what the TypeScript reference compiler emits today', () => {
    expect(derived).toEqual(checkedIn);
  });

  it('covers every emitter under every flag combination', () => {
    const names = Object.keys(checkedIn.emitters);
    expect(names.length).toBeGreaterThanOrEqual(24);
    for (const name of names) {
      for (const v of Object.keys(VARIANTS)) {
        expect(checkedIn.emitters[name][v], `${name}/${v}`).toBeDefined();
        expect(checkedIn.emitters[name][v].sha256).toMatch(/^[0-9a-f]{64}$/);
      }
    }
  });

  it('is non-vacuous: the flags actually move bytes', () => {
    // A fixture where every variant hashed the same would pass in a tier that
    // ignored the flags entirely. Pin that the reference really diverges.
    const e = checkedIn.emitters;
    expect(e.EcMul.pool.sha256).not.toBe(e.EcMul.off.sha256);
    expect(e.EcMul.sink.sha256).not.toBe(e.EcMul.pool.sha256);
    expect(e.EcMulGen.comb.sha256).not.toBe(e.EcMulGen.sink.sha256);
    expect(e.P256MulGen.comb.sha256).not.toBe(e.P256MulGen.sink.sha256);
    expect(e.P384MulGen.comb.sha256).not.toBe(e.P384MulGen.sink.sha256);
    expect(e.VerifyECDSA_P256.comb.sha256).not.toBe(e.VerifyECDSA_P256.sink.sha256);
  });

  it('the comb only fires where the base is a compile-time constant', () => {
    // `ecMul` / `p256Mul` take their base at run time, so the comb cannot
    // apply. A tier that "optimized" those would be combing an attacker-chosen
    // point, and the interval argument in comb.ts does not cover that.
    const e = checkedIn.emitters;
    for (const n of ['EcMul', 'P256Mul', 'P384Mul']) {
      expect(e[n].comb.sha256, n).toBe(e[n].sink.sha256);
    }
  });
});
