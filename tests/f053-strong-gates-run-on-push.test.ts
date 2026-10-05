/**
 * F-053 — the three strongest CI gates ran on pull_request only.
 *
 * `cross-compiler-bytewise.yml` (full corpus x 7 tiers + Lean), `differential.yml`
 * (the only oracle graded against an engine outside this codebase) and ci.yml's
 * `golden-provenance-gate` job (`if: github.event_name == 'pull_request'`) were
 * all skipped on a direct push to main. ci.yml's own wire-format gate comment
 * records that most commits reach main that way (bd7ec284 was one), so on most
 * commits none of the three ran.
 *
 * What this proves:
 *   - both workflows declare `push` (branches include main) and `merge_group`
 *     triggers, beside the existing `pull_request`;
 *   - the provenance gate job carries no `if:` that restricts it to one event;
 *   - the gate's base-resolution shell, run for real against a scratch git
 *     repo with a stub `node`, hands check-golden-provenance.mjs the right base
 *     for each event: for pull_request, the LIVE tip of the branch the PR
 *     merges into (resolved from base.ref at run time, not the stale captured
 *     base.sha -- F-163, the same staleness hazard the sibling wire-format
 *     gate documents and avoids the same way); the merge-group base SHA; the
 *     pushed-over tip; and HEAD^ when the push has no usable `before`
 *     (all-zero SHA on a new branch or tag, or a force-pushed-away commit that
 *     is not in the clone).
 *
 * What it does not prove: GitHub Actions cannot run here, so nothing shows the
 * workflows actually start on those events, that GitHub populates the event
 * fields as documented, or that the gates pass. The YAML is read as text
 * (there is no YAML parser among the root dependencies), so a shape this test
 * does not recognise fails it rather than passing it.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf-8');

/** Drop full-line comments so a trigger mentioned in prose does not count. */
const codeLines = (text: string) => text.split('\n').filter((l) => !/^\s*#/.test(l));

/** The lines of an indented block that starts at `header` (exact line match). */
function block(lines: string[], header: RegExp): string[] | undefined {
  const start = lines.findIndex((l) => header.test(l));
  if (start < 0) return undefined;
  const indent = lines[start]!.match(/^ */)![0].length;
  const out: string[] = [];
  for (const l of lines.slice(start + 1)) {
    if (l.trim() === '') continue;
    if (l.match(/^ */)![0].length <= indent) break;
    out.push(l);
  }
  return out;
}

/** Trigger name -> its body lines, for the top-level `on:` block. */
function triggers(file: string): Map<string, string[]> {
  const lines = codeLines(read(file));
  const on = block(lines, /^on:\s*$/);
  expect(on, `${file}: no top-level "on:" block`).toBeDefined();
  const out = new Map<string, string[]>();
  for (const l of on!) {
    const m = /^ {2}([a-z_]+):\s*$/.exec(l);
    if (m) out.set(m[1]!, block(on!, new RegExp(`^ {2}${m[1]}:\\s*$`)) ?? []);
  }
  return out;
}

describe('F-053: the strongest gates run on push to main and on merge_group', () => {
  for (const file of ['.github/workflows/cross-compiler-bytewise.yml', '.github/workflows/differential.yml']) {
    it(`${file} triggers on pull_request, push (main) and merge_group`, () => {
      const t = triggers(file);
      expect([...t.keys()], file).toEqual(expect.arrayContaining(['pull_request', 'push', 'merge_group']));
      const branches = t.get('push')!.join('\n');
      expect(branches, `${file}: push trigger does not cover main`).toMatch(/branches:\s*\[[^\]]*\bmain\b/);
    });
  }

  const job = () => {
    const lines = codeLines(read('.github/workflows/ci.yml'));
    const body = block(lines, /^ {2}golden-provenance-gate:\s*$/);
    expect(body, 'ci.yml: golden-provenance-gate job not found').toBeDefined();
    return body!;
  };

  it('ci.yml golden-provenance-gate has no event-restricting if:', () => {
    const ifs = job().filter((l) => /^ {4}if:/.test(l));
    expect(ifs, 'job-level if: still scopes the gate to some events').toEqual([]);
  });

  /** The `run: |` script of the provenance-check step, dedented. */
  function checkScript(): { env: string[]; script: string } {
    const body = job();
    const step = body.findIndex((l) => /- name: Check golden\/vector provenance/.test(l));
    expect(step, 'provenance check step not found').toBeGreaterThanOrEqual(0);
    const rest = body.slice(step + 1);
    const end = rest.findIndex((l) => /^ {6}- /.test(l));
    const stepLines = end < 0 ? rest : rest.slice(0, end);
    const env = block(stepLines, /^ {8}env:\s*$/) ?? [];
    const run = block(stepLines, /^ {8}run: \|\s*$/);
    expect(run, 'provenance check step has no multi-line run: | script').toBeDefined();
    const pad = Math.min(...run!.map((l) => l.match(/^ */)![0].length));
    return { env, script: run!.map((l) => l.slice(pad)).join('\n') + '\n' };
  }

  it('ci.yml golden-provenance-gate maps every event payload into env', () => {
    const env = checkScript().env.join('\n');
    // PR_BASE_REF, not PR_BASE_SHA: base.sha is the base tip as of the PR's
    // last sync and goes stale when another PR merges into the target branch
    // in the meantime (F-163) -- the same hazard the sibling wire-format gate
    // documents and avoids by resolving the live branch ref at run time.
    expect(env).toMatch(/PR_BASE_REF:\s*\$\{\{\s*github\.event\.pull_request\.base\.ref\s*\}\}/);
    expect(env).toMatch(/MERGE_GROUP_BASE:\s*\$\{\{\s*github\.event\.merge_group\.base_sha\s*\}\}/);
    expect(env).toMatch(/PUSH_BEFORE:\s*\$\{\{\s*github\.event\.before\s*\}\}/);
  });

  it('ci.yml golden-provenance-gate resolves a base for every event type', () => {
    const { script } = checkScript();
    expect(script, 'the run script interpolates ${{ }} instead of reading env').not.toMatch(/\$\{\{/);

    const dir = mkdtempSync(join(tmpdir(), 'f053-'));
    try {
      const git = (...a: string[]) => {
        const r = spawnSync('git', a, { cwd: dir, encoding: 'utf-8' });
        expect(r.status, `git ${a.join(' ')}: ${r.stderr}`).toBe(0);
        return r.stdout.trim();
      };
      git('init', '-q');
      git('-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '--allow-empty', '-m', 'a');
      const a = git('rev-parse', 'HEAD');
      git('-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '--allow-empty', '-m', 'b');
      const b = git('rev-parse', 'HEAD');
      // Simulate actions/checkout@v4 (fetch-depth: 0) having already fetched
      // origin/main at its CURRENT tip (b) -- later than the PR's
      // last-synced base.sha (a), exactly as happens when another PR merges
      // into main in the meantime (F-163).
      git('update-ref', 'refs/remotes/origin/main', b);

      // Stub `node` so the script's final call reports the base it was given.
      const bin = join(dir, 'stub-bin');
      spawnSync('mkdir', ['-p', bin]);
      writeFileSync(join(bin, 'node'), '#!/bin/sh\necho "BASE=${GOLDEN_GATE_BASE:-}|ARGS=$*"\n');
      chmodSync(join(bin, 'node'), 0o755);
      writeFileSync(join(dir, 'gate.sh'), script);

      const run = (env: Record<string, string>) => {
        const r = spawnSync('bash', ['gate.sh'], {
          cwd: dir,
          encoding: 'utf-8',
          env: { PATH: `${bin}:${process.env.PATH}`, HOME: dir, ...env },
        });
        expect(r.status, r.stderr).toBe(0);
        const m = /BASE=([^|\n]*)\|ARGS=(.*)/.exec(r.stdout);
        expect(m, `script never invoked node: ${r.stdout}`).not.toBeNull();
        expect(m![2], 'checker invoked with unexpected args').toMatch(/check-golden-provenance\.mjs/);
        return m![1];
      };

      const zero = '0'.repeat(40);
      const missing = 'f'.repeat(40);
      // F-163 regression: `a` stands in for the PR's captured base.sha, now
      // stale -- origin/main has since moved to `b` (another PR merged in the
      // meantime). The gate must hand the checker a ref that re-resolves to
      // the CURRENT tip (origin/main), not the stale sha `a`.
      expect(run({ PR_BASE_SHA: a, PR_BASE_REF: 'main' }), 'pull_request (stale base.sha)').toBe(
        'origin/main',
      );
      expect(run({ MERGE_GROUP_BASE: a }), 'merge_group').toBe(a);
      expect(run({ PUSH_BEFORE: a }), 'push').toBe(a);
      expect(run({ PUSH_BEFORE: zero }), 'push, new branch / tag').toBe(git('rev-parse', `${b}^`));
      expect(run({ PUSH_BEFORE: missing }), 'push, force-pushed-away tip').toBe(a);
      expect(run({}), 'workflow_dispatch').toBe(a);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
