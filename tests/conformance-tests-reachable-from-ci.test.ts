/**
 * Every test file under `conformance/` must be reachable from CI.
 *
 * `conformance/` is NOT a pnpm workspace member — `pnpm-workspace.yaml` lists
 * only `packages/*` and `integration/ts` — so `turbo run test` never descends
 * into it, and `conformance/`'s own `npm test` runs the conformance *runner*,
 * not vitest. A test file there is executed only if some workflow names its
 * path explicitly. Nothing enforced that, so four directories were never run
 * by CI at all:
 *
 *   conformance/codepart-pin      (R-010, this branch)
 *   conformance/dce               (N-140, this branch)
 *   conformance/source-map        (audit #22)
 *   conformance/subtype-parity    (N-121)
 *
 * 146 passing tests that no pipeline executed. Two of them were added during
 * the remediation pass that was meant to be closing gaps of exactly this kind:
 * a guard is only as real as the thing that runs it, and adding a test file to
 * a directory CI cannot see produces coverage that exists only on the machine
 * of whoever wrote it.
 *
 * This is the same defect the fuzzer harness had one directory over
 * (`conformance/fuzzer/__tests__`, 64 assertions, executed by nothing), and
 * the same shape as R-110 and R-111 — which pin the OTHER halves of this
 * problem: that a gate's tier list and its case count match what the code
 * requires. This pins that the gate runs at all.
 *
 * Workflows invoke these paths in two forms — repo-relative
 * (`npx vitest run conformance/fuzzer/__tests__/`) and relative to a
 * `conformance` working directory (`npx vitest run negatives/`) — so both are
 * accepted here. A future third form needs adding, and the failure message
 * says so rather than leaving the next person to guess.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOWS = join(ROOT, '.github', 'workflows');

/**
 * Every TRACKED `*.test.ts` / `*.spec.ts` under conformance/, repo-relative.
 *
 * Tracked only: CI runs what is committed, and an untracked file is either
 * scratch or another contributor's work in progress. Walking the filesystem
 * instead would make this guard's verdict depend on whatever happens to be
 * sitting in the working tree.
 */
function conformanceTestFiles(): string[] {
  const out = execFileSync('git', ['ls-files', 'conformance'], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  return out
    .split('\n')
    .filter((f) => /\.(test|spec)\.(ts|mts|js)$/.test(f))
    .sort();
}

/**
 * Only lines that actually INVOKE vitest count.
 *
 * Scanning whole-file text would let prose vouch for execution: `source-map`
 * appears in two ci.yml comments and in neither case is that directory run.
 * A path mentioned in a comment is documentation, not coverage, and counting
 * it is the same substring-matching mistake this guard exists to expose.
 */
function haystack(): string {
  const texts = [readFileSync(join(ROOT, 'package.json'), 'utf8')];
  for (const f of readdirSync(WORKFLOWS)) {
    const p = join(WORKFLOWS, f);
    if (statSync(p).isFile()) texts.push(readFileSync(p, 'utf8'));
  }
  const cp = join(ROOT, 'conformance', 'package.json');
  if (existsSync(cp)) texts.push(readFileSync(cp, 'utf8'));

  // A vitest invocation can span lines: YAML folded scalars (`run: >`) put the
  // command on one line and its arguments on following, more-indented ones. A
  // per-line filter would see `npx vitest run` and none of its paths. So when a
  // line invokes vitest, keep it AND its continuation block.
  const lines = texts.join('\n').split('\n');
  const kept: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/^\s*#/.test(line) || !/vitest/.test(line)) continue;
    kept.push(line);
    const indent = line.search(/\S/);
    for (let j = i + 1; j < lines.length; j++) {
      const next = lines[j]!;
      if (next.trim() === '') { kept.push(next); continue; }
      if (next.search(/\S/) <= indent) break;
      if (/^\s*#/.test(next)) continue; // a comment inside the block is still prose
      kept.push(next);
    }
  }
  return kept.join('\n');
}

/** Reachable if the file, or any ancestor dir, is named in either form. */
function isReachable(file: string, hay: string): boolean {
  const rel = file.replace(/^conformance\//, '');
  const candidates = new Set<string>([file, rel]);
  for (const form of [file, rel]) {
    const segs = form.split('/');
    // Stop BELOW the conformance root. An ancestor of `conformance` alone —
    // or the bare prefix `conformance/` — matches essentially every workflow
    // line and would make this guard pass for every file, which is the exact
    // class of defect it exists to catch. Only directories strictly inside
    // conformance/ count as "named".
    const floor = form === file ? 2 : 1;
    for (let i = segs.length - 1; i >= floor; i--) {
      const d = segs.slice(0, i).join('/');
      candidates.add(d);
      candidates.add(d + '/');
    }
  }
  // Match as a PATH TOKEN, not a bare substring. `dce` occurs inside ordinary
  // prose (and inside this guard's own explanatory comments), and counting that
  // makes the check pass for a directory nothing runs — the very defect it is
  // here to catch. A path counts only when delimited by whitespace, a quote, or
  // a shell separator on both sides.
  const DELIM = String.raw`[\s"'\`=;&|()]`;
  for (const c of candidates) {
    if (!c || c === 'conformance' || c === 'conformance/') continue;
    const esc = c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(^|${DELIM})${esc}($|${DELIM})`, 'm');
    if (re.test(hay)) return true;
  }
  return false;
}

describe('every conformance test file is reachable from CI', () => {
  const files = conformanceTestFiles();
  const hay = haystack();

  it('finds a non-trivial number of conformance test files', () => {
    // Anti-vacuity: if the walk breaks, every other assertion passes silently.
    expect(files.length).toBeGreaterThan(40);
  });

  it('names every one of them in a workflow or package script', () => {
    const unreachable = files.filter((f) => !isReachable(f, hay));
    expect(
      unreachable,
      `these conformance test files are executed by nothing in CI — turbo does ` +
        `not descend into conformance/ (it is not a pnpm workspace member), so a ` +
        `workflow must name the path explicitly. Add a step, or a new invocation ` +
        `form to isReachable() if one was introduced:\n  ${unreachable.join('\n  ')}`,
    ).toEqual([]);
  });
});
