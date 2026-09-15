import { describe, it, expect } from 'vitest';
import {
  decideMissingTierAction,
  coverageShortfallError,
} from '../run.js';

// A tier attaches by dropping `tools/analyzer-runner/<tier>.sh`. Deleting or
// renaming a wrapper used to turn its 8 fixtures into `skip`, and the driver
// exited 0 — a 48/56 run reported as success while the file header claimed
// "8 fixtures x 7 tiers, 56/56". These two pure functions are what make the
// claim checkable. Mirrors conformance/runner/runner.ts
// `decideMissingCompilerAction` / `emptyFixtureSetError` deliberately.

describe('decideMissingTierAction', () => {
  it('is ok when every selected tier has a wrapper', () => {
    expect(decideMissingTierAction([], {})).toBe('ok');
    expect(decideMissingTierAction([], { CI: 'true' })).toBe('ok');
  });

  it('only warns locally, so a dev without a toolchain can still run it', () => {
    expect(decideMissingTierAction(['zig'], {})).toBe('warn');
    expect(decideMissingTierAction(['zig', 'java'], { CI: 'false' })).toBe('warn');
  });

  it('fails hard under CI', () => {
    expect(decideMissingTierAction(['zig'], { CI: 'true' })).toBe('fail');
  });

  it('fails hard under RUNAR_CONFORMANCE_STRICT', () => {
    expect(decideMissingTierAction(['zig'], { RUNAR_CONFORMANCE_STRICT: '1' })).toBe('fail');
    expect(decideMissingTierAction(['zig'], { RUNAR_CONFORMANCE_STRICT: 'true' })).toBe('fail');
  });
});

describe('coverageShortfallError', () => {
  const ctx = { tiers: 7, fixtures: 8 };

  it('is silent when every selected pair passed', () => {
    expect(coverageShortfallError(56, ctx)).toBeNull();
  });

  it('reports the shortfall when a wrapper went missing', () => {
    const msg = coverageShortfallError(48, ctx);
    expect(msg).not.toBeNull();
    expect(msg).toContain('48');
    expect(msg).toContain('56');
  });

  it('refuses a run that evaluated nothing', () => {
    // 0 passes with 0 fails and 0 errors is the shape a fully-detached
    // matrix produces, and it exited 0.
    expect(coverageShortfallError(0, ctx)).not.toBeNull();
  });
});
