import { describe, it, expect } from 'vitest';
import { decideExitCode, decideGoldenWrite } from './run.js';

// N-088 (companion to the conformance/runner/index.ts --update-golden fix):
// `conformance/source-map/run.ts --update` had two instances of the same
// fail-open class.
//
//   (a) `writeFileSync(goldenPath, emitted)` under `--update` ran
//       unconditionally — a compile that produced a structurally invalid
//       source map, or one whose mappings failed the independent
//       source-anchor oracle, still got STAMPED as the new golden.
//   (b) the final exit check was `if (failed > 0 && !update) process.exit(1)`
//       — any failure found while regenerating (including the one (a) just
//       wrote to disk) was masked by the mere fact of running `--update`.
//
// `decideGoldenWrite` and `decideExitCode` are the two decisions this file's
// `main()` now delegates to. Importing `run.ts` does NOT run its CLI (the
// entry-point guard at the bottom only calls `main()` when this file is the
// process entry point), so these pure functions can be unit-tested without
// spawning any of the seven compilers.
//
// What this proves: given the inputs that correspond to a fixture whose
// structural or anchor check failed, the golden is not written under
// --update, and the overall run reports a non-zero exit code regardless of
// --update.
// What it does not prove: anything about the structural/anchor checks
// themselves, or about any real fixture's source map.

describe('N-088: source-map run.ts --update does not mask a failing fixture', () => {
  it('writes the golden under --update only when both checks pass', () => {
    expect(decideGoldenWrite(true, true)).toBe(true);
    expect(decideGoldenWrite(false, true)).toBe(false);
    expect(decideGoldenWrite(true, false)).toBe(false);
    expect(decideGoldenWrite(false, false)).toBe(false);
  });

  it('a nonzero failure count is a nonzero exit code, with or without --update', () => {
    expect(decideExitCode(1, true)).not.toBe(0);
    expect(decideExitCode(1, false)).not.toBe(0);
    expect(decideExitCode(0, true)).toBe(0);
    expect(decideExitCode(0, false)).toBe(0);
  });
});
