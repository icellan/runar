/**
 * The provenance gate must give the same verdict from any directory.
 *
 * `parseArgs` defaulted `root` to `process.cwd()`, while every path the gate
 * handles — the changed set from `git diff --name-only`, the allowlist's `path`
 * fields, witness locations — is repo-relative. Run from anywhere but the repo
 * root, every allowlist lookup missed, and the gate reported EVERY changed
 * golden as "no cross-check co-change and no allowlist entry" and exited 1.
 *
 * Measured before the fix, on a tree whose true answer is 122 justified /
 * exit 0: run from `conformance/` it announced 122 unjustified goldens and
 * exited 1. That directory is where every other conformance command in this
 * repo is run from, so it was the likely cwd, not an exotic one.
 *
 * This is the worst shape a guard can fail in — loud, total, and plausible.
 * A silent pass gets caught eventually by the thing it failed to guard; a
 * confident false alarm gets acted on. It cost one agent a wrong report, cost
 * the reviewer of that report a wrong diagnosis on top of it ("misread the
 * header" — it had not), and the obvious remedy for the phantom failure is to
 * mass-restamp provenance that was never stale, which would have destroyed the
 * real record to silence a bug in the reader.
 *
 * The fix resolves `root` from `git rev-parse --show-toplevel`. This asserts
 * the property that matters — same verdict, any cwd — rather than the
 * implementation, so a future rewrite that keeps the property passes.
 */

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const GATE = join(ROOT, 'conformance', 'scripts', 'check-golden-provenance.mjs');

/** Runs the gate from `cwd` and returns its exit code and stdout+stderr. */
function runGate(cwd: string): { code: number; out: string } {
  try {
    const out = execFileSync('node', [GATE, '--base', 'origin/main'], {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 32 * 1024 * 1024,
    });
    return { code: 0, out };
  } catch (e) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    return { code: err.status ?? -1, out: (err.stdout ?? '') + (err.stderr ?? '') };
  }
}

describe('the golden-provenance gate does not depend on the caller cwd', () => {
  const fromRoot = runGate(ROOT);
  const fromConformance = runGate(join(ROOT, 'conformance'));

  it('gives the same exit code from the repo root and from conformance/', () => {
    expect(
      fromConformance.code,
      'the gate disagrees with itself depending on where it is invoked. Every ' +
        'path it handles is repo-relative, so `root` must come from ' +
        '`git rev-parse --show-toplevel`, not from process.cwd().\n' +
        `from repo root:   exit ${fromRoot.code}\n` +
        `from conformance: exit ${fromConformance.code}`,
    ).toBe(fromRoot.code);
  });

  it('reports the same number of unjustified goldens from both', () => {
    // Counting the failure marks rather than trusting the exit code alone: the
    // original defect produced a DIFFERENT set of complaints, not merely a
    // different status, and a future variant could plausibly agree on the code
    // while disagreeing on the contents.
    const marks = (s: string) => (s.match(/✗/g) ?? []).length;
    expect(marks(fromConformance.out)).toBe(marks(fromRoot.out));
  });

  it('is not vacuous: the gate actually ran and examined goldens', () => {
    // Anti-vacuity. If the gate crashed on startup from both directories it
    // would "agree" perfectly and prove nothing — which is the exact class of
    // guard this branch keeps finding. Require the header that only a real run
    // emits.
    expect(
      fromRoot.out,
      'the gate produced no summary line from the repo root, so the agreement ' +
        'asserted above is between two non-runs',
    ).toMatch(/golden\/vector file\(s\) changed/);
  });
});
