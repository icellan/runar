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
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const GATE = join(ROOT, 'conformance', 'scripts', 'check-golden-provenance.mjs');

/**
 * A golden the gate must JUSTIFY at this tree: the first allowlist entry whose
 * pinned sha256 matches the file's current bytes. Chosen dynamically so the
 * test does not rot when one pin is legitimately re-stamped.
 */
function justifiedGolden(): string | undefined {
  const allowlist = JSON.parse(
    readFileSync(join(ROOT, 'conformance', 'golden-provenance-allowlist.json'), 'utf8'),
  ) as { entries?: { path: string; sha256: string }[] };
  return (allowlist.entries ?? []).find((e) => {
    const abs = join(ROOT, e.path);
    return (
      existsSync(abs) && createHash('sha256').update(readFileSync(abs)).digest('hex') === e.sha256
    );
  })?.path;
}

/** Runs the gate from `cwd` and returns its exit code and stdout+stderr. */
function runGate(cwd: string, args: string[] = ['--base', 'origin/main']): { code: number; out: string } {
  try {
    const out = execFileSync('node', [GATE, ...args], {
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

  it('is not vacuous: the gate actually ran from both directories', () => {
    // Anti-vacuity for the `--base origin/main` pair. If the gate crashed on
    // startup from both directories it would "agree" perfectly and prove
    // nothing. Either summary form is a real run: a tree with no golden diff
    // against origin/main (origin/main itself, any clean branch) legitimately
    // prints "no golden/vector files changed", so requiring the non-empty form
    // here made this test red everywhere except on a branch that happened to
    // move a golden (F-000). The examined-count is asserted by the pinned-set
    // tests below, which do not depend on the diff.
    const summary =
      /Golden-provenance gate: (?:no golden\/vector files changed|\d+ golden\/vector file\(s\) changed)/;
    expect(fromRoot.out, 'no gate summary from the repo root').toMatch(summary);
    expect(fromConformance.out, 'no gate summary from conformance/').toMatch(summary);
  });

  // The pair above is vacuous for the cwd property on a tree with no golden
  // diff: both runs print "nothing to justify" whatever `root` resolves to. So
  // the property is ALSO checked against a pinned changed set containing one
  // golden that is justified at this tree. Under the original defect
  // (root = process.cwd()) the run from conformance/ cannot find the allowlist,
  // reports that golden as unjustified and exits 1, while the repo-root run
  // justifies it and exits 0 — so these assertions go red.
  //
  // Proves: with a non-empty golden set, the gate examines it and reaches the
  // same verdict from the repo root and from conformance/.
  // Does not prove: that `git diff` discovery of the changed set is itself
  // cwd-independent (the `--base` pair covers that only when the diff is
  // non-empty), nor anything about the correctness of the allowlist pins.
  const golden = justifiedGolden();
  const pinnedArgs = golden ? ['--files', golden] : [];
  const pinnedFromRoot = golden ? runGate(ROOT, pinnedArgs) : { code: -1, out: '' };
  const pinnedFromConformance = golden
    ? runGate(join(ROOT, 'conformance'), pinnedArgs)
    : { code: -1, out: '' };

  it('has a golden that is justified at this tree to drive the gate with', () => {
    expect(
      golden,
      'no allowlist entry pins its golden\'s current bytes, so the pinned-set ' +
        'checks below cannot discriminate a cwd-dependent gate from a correct one',
    ).toBeDefined();
  });

  it('examines the pinned golden and justifies it from the repo root', () => {
    expect(pinnedFromRoot.out).toMatch(/Golden-provenance gate: 1 golden\/vector file\(s\) changed/);
    expect(pinnedFromRoot.out).toContain(`✓ ${golden}`);
  });

  it('gives the same verdict on the pinned golden from conformance/', () => {
    expect(
      pinnedFromConformance.code,
      `from repo root:   exit ${pinnedFromRoot.code}\n${pinnedFromRoot.out}\n` +
        `from conformance: exit ${pinnedFromConformance.code}\n${pinnedFromConformance.out}`,
    ).toBe(pinnedFromRoot.code);
    expect(pinnedFromConformance.out).toContain(`✓ ${golden}`);
  });
});
