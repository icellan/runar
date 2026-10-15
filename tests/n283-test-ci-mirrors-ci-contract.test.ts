/**
 * N-283 — `pnpm test:ci` vs `.github/workflows/ci.yml` drift: the "green
 * here -> green CI" contract (README.md's `pnpm test:ci` row, and
 * CONTRIBUTING.md's "Mirrors CI") was never counted. F-253 flagged the claim
 * in passing ("the wider claim that `pnpm test:ci` skips CI gates and runs
 * one CI does not — not re-counted here; N-283") but did not measure it.
 *
 * This test measures it. It parses every `run:` step in every ci.yml job and
 * every command `pnpm run test:ci` expands to (recursively, following
 * `pnpm run <name>` references), and diffs them.
 *
 * The result: far more than the "~18" F-253 guessed. `pnpm test:ci` never
 * runs the FULL native unit-test suite for 5 of 6 non-TS SDK packages (only
 * a single narrow wallet-client test per tier, via a DIFFERENT command), the
 * full Go/Rust compiler suites (only a `-run`-filtered / `--test`-filtered
 * subset via `conformance:go`/`conformance:rust`), five whole conformance
 * vitest directories (`negatives/`, `go-only-parity/`, `closed-findings/`,
 * `preimage-binding/`, `witnesses/`), the script-execution oracle, the
 * sdk-vertical pins, the decompiler fingerprint/template drift checks, the
 * mutation-corpus and analyzer gates, and all four merge-base-diffing lint
 * gates (golden-provenance, wire-format, their self-tests aside).
 *
 * Rather than blindly wiring ~60 more commands into `test:ci` — several need
 * a merge-base this isn't a PR, and NONE of this was executed here to
 * confirm it would pass (the remediation rules forbid a "confident wrong
 * fix") — this pins the measured gap, categorized by why it exists, and
 * rewords the contract (README.md / CONTRIBUTING.md) to point at this test
 * instead of promising an unconditional mirror. The `addable-locally`
 * category (no merge-base, no network, no service — just never wired) is
 * the follow-up candidate: every line in it could be added to `test:ci`
 * without first needing a merge-base or a running node.
 *
 * Categories:
 *   - addable-locally:      nothing blocks running it in a plain local clone;
 *                           simply never wired into a `pnpm run` chain.
 *   - needs-merge-base:     the gate diffs `<base>...HEAD`; there is no base
 *                           outside a PR/push/merge_group event.
 *   - transitive-via-turbo: not literally the same text, but `turbo run
 *                           test`/`typecheck` already runs it because it is
 *                           the named package's own `test`/`typecheck`
 *                           script (verified against that package's
 *                           package.json) or because `test`/`typecheck`
 *                           `dependsOn` `build` in turbo.json.
 *   - transitive-via-script: a sibling command in the same job already
 *                           performs the work as a side effect (e.g.
 *                           `gradle test` compiles before testing, making an
 *                           explicit `gradle build` step redundant).
 *   - covered-by-wrapper:   the whole JOB is mirrored by a wrapper script
 *                           test:ci already calls, matched by name/semantics
 *                           rather than literal text — `runar-verification`
 *                           by `scripts/lean-verify.sh` (kept in sync by
 *                           tests/f174-lean-verify-mirrors-ci.test.ts) and
 *                           `integration` by `integration/run-all.sh`
 *                           (verified by hand against every per-tier step).
 *   - needs-opt-in:         `integration-teranode` only runs on an explicit
 *                           `workflow_dispatch` flag; it is never part of a
 *                           default push/PR/merge_group run either.
 *
 * What this test proves: the measured set of ci.yml run-steps with no exact
 * (or `cd DIR &&` / directory-prefix / path-style) equivalent anywhere in
 * `pnpm run test:ci`'s expansion is exactly the pinned, categorized list
 * below — so a NEW gap (a ci.yml step added with nothing in test:ci reaching
 * it, or an existing equivalence that stops holding because test:ci's chain
 * changed) fails this test instead of silently widening the gap further.
 * Also: no ci.yml text names any "wallet-client" family test — the one
 * direction where `test:ci` runs something (seven per-tier wallet-client
 * commands) that CI runs NOTHING like, by design (env-gated, skip clean).
 *
 * What this test does not prove: that any of the `addable-locally` lines
 * WOULD pass if wired into `test:ci` — several were never executed as part
 * of this remediation. It does not prove the `transitive-via-turbo` /
 * `transitive-via-script` claims by executing turbo or gradle; those are
 * verified by reading the dependency declarations (turbo.json `dependsOn`,
 * the named package's own scripts) once and cited in the comments, not
 * re-derived at runtime. A shell-syntax form this parser does not recognise
 * (a new YAML scalar style, a step with no `run:`, a wrapper job added
 * without updating JOB_EXPLANATIONS) fails loudly rather than passing
 * vacuously — see the floor assertions.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel: string) => readFileSync(resolve(REPO, rel), 'utf-8');

/** Drop full-line comments (also strips bash comments inside `run:` blocks —
 * those are not commands, so dropping them is correct here too). */
const codeLines = (text: string) => text.split('\n').filter((l) => !/^\s*#/.test(l));

/** Lines after `startIdx` indented strictly more than `headerIndent`, up to
 * (not including) the first line that dedents back to `headerIndent` or
 * less. Blank lines are skipped without ending the block. */
function block(lines: string[], startIdx: number, headerIndent: number): string[] {
  const out: string[] = [];
  for (let i = startIdx; i < lines.length; i++) {
    const l = lines[i]!;
    if (l.trim() === '') continue;
    const indent = l.match(/^ */)![0].length;
    if (indent <= headerIndent) break;
    out.push(l);
  }
  return out;
}

function blockByHeader(lines: string[], header: RegExp): string[] | undefined {
  const start = lines.findIndex((l) => header.test(l));
  if (start < 0) return undefined;
  const indent = lines[start]!.match(/^ */)![0].length;
  return block(lines, start + 1, indent);
}

interface RawJob {
  id: string;
  lines: string[];
}

/** Top-level `jobs:` entries, in file order, with their body lines. */
function parseJobs(ciText: string): RawJob[] {
  const lines = codeLines(ciText);
  const jobsBlock = blockByHeader(lines, /^jobs:\s*$/);
  if (!jobsBlock) return [];
  const re = /^ {2}([A-Za-z0-9_-]+):\s*$/;
  const out: RawJob[] = [];
  let cur: RawJob | null = null;
  for (const l of jobsBlock) {
    const indent = l.match(/^ */)![0].length;
    const m = re.exec(l);
    if (m && indent === 2) {
      if (cur) out.push(cur);
      cur = { id: m[1]!, lines: [] };
    } else if (cur) {
      cur.lines.push(l);
    }
  }
  if (cur) out.push(cur);
  return out;
}

/** A job's `steps:` list, split into one line-group per `- ` item. The
 * item's own "      - " prefix is replaced with 8 spaces so its first field
 * (`run:`, `name:`, `uses:`, ...) sits at the same indent as the rest of the
 * step's fields, letting a single regex find a field regardless of whether
 * it was the item's first line or a later one. */
function splitSteps(jobLines: string[]): string[][] {
  const stepsBlock = blockByHeader(jobLines, /^ {4}steps:\s*$/);
  if (!stepsBlock) return [];
  const out: string[][] = [];
  let cur: string[] | null = null;
  for (const l of stepsBlock) {
    const indent = l.match(/^ */)![0].length;
    if (indent === 6 && l.slice(6).startsWith('- ')) {
      if (cur) out.push(cur);
      cur = ['        ' + l.slice(8)];
    } else if (cur) {
      cur.push(l);
    }
  }
  if (cur) out.push(cur);
  return out;
}

function extractField(stepLines: string[], field: string): string | undefined {
  const re = new RegExp(`^ {8}${field}:\\s*(.+)$`);
  for (const l of stepLines) {
    const m = re.exec(l);
    if (m) return m[1]!.trim();
  }
  return undefined;
}

/** The step's `run:` value, as a list of raw (un-merged, un-normalized)
 * lines: a `|`/`|-` literal block keeps its newlines; a `>`/`>-` folded
 * block is joined into one line (no blank-line paragraph breaks occur in
 * this file's folded blocks, so plain space-joining is exact); an inline
 * `run: <cmd>` is a single line. */
function extractRunLines(stepLines: string[]): string[] | null {
  const runIdx = stepLines.findIndex((l) => /^ {8}run:/.test(l));
  if (runIdx < 0) return null;
  const m = /^ {8}run:\s*(.*)$/.exec(stepLines[runIdx]!)!;
  const rest = m[1]!;
  if (rest === '|' || rest === '|-') {
    return block(stepLines, runIdx + 1, 8).map((l) => l.trim());
  }
  if (rest === '>' || rest === '>-') {
    return [block(stepLines, runIdx + 1, 8).map((l) => l.trim()).join(' ')];
  }
  return [rest.trim()];
}

/** A bare `cd DIR` line (no `&&`) applies to every line after it in the same
 * run block, same as a real shell. Merges it in as a `cd DIR && ` prefix and
 * drops the bare line (it is not itself a command). */
function mergeCd(lines: string[]): string[] {
  const out: string[] = [];
  let prefix = '';
  for (const raw of lines) {
    const l = raw.trim();
    const cdOnly = /^cd\s+(\S+)$/.exec(l);
    if (cdOnly) {
      prefix = `cd ${cdOnly[1]} && `;
      continue;
    }
    out.push(prefix + l);
  }
  return out;
}

/** Minimal normalization: collapse whitespace, canonicalize `python` (no
 * version) to `python3` as its own token, and drop a trailing `/` on any
 * token longer than one character (so `tests/` and `tests` compare equal,
 * same rule as tests/ci-covers-root-tests.test.ts). Deliberately NOT
 * aggressive: flag differences (extra `-v`, a glob vs. no glob, a missing
 * env var) stay real differences rather than being normalized to green. */
function normalize(s: string): string {
  return s
    .trim()
    .replace(/\s+/g, ' ')
    .replace(/(^|\s)python(?!3)(?=\s|$)/g, '$1python3')
    .split(' ')
    .map((tok) => (tok.length > 1 ? tok.replace(/\/$/, '') : tok))
    .join(' ');
}

/** True when `local` holds "npx vitest run <dir>" (bare directory, no file)
 * and `ciLine` is "npx vitest run <dir>/<anything>" — the directory form
 * already runs every file under it. */
function dirContainsFile(localSet: Set<string>, ciLine: string): boolean {
  const m = /^npx vitest run (\S+)$/.exec(ciLine);
  if (!m) return false;
  const parts = m[1]!.split('/');
  for (let i = 1; i < parts.length; i++) {
    if (localSet.has(`npx vitest run ${parts.slice(0, i).join('/')}`)) return true;
  }
  return false;
}

/** `cd DIR && npx vitest run X` / `cd DIR && npx tsx X` and `npx vitest run
 * DIR/X` / `npx tsx DIR/X` reach the identical file two ways: cwd-relative
 * (most ci.yml steps) vs. repo-root-relative (most package.json scripts).
 * Produces the repo-root-relative alias so the PATH STYLE isn't mistaken for
 * a coverage gap; a real gap (no local script at all) still has no alias
 * present in `localLines` either. */
function pathJoinedAlias(line: string): string | null {
  const m = /^cd (\S+) && (npx (?:vitest run|tsx)) (.+)$/.exec(line);
  if (!m) return null;
  return `${m[2]} ${m[1]}/${m[3]}`;
}

const SETUP_EXCLUDE =
  /^(pnpm install\b|npm ci\b|pip install\b|chmod \+x\b|find \.turbo\/cache\b|git (fetch|rev-parse|cat-file|update-ref)\b|mkdir -p\b|bundle install\b)/;
/** A command line, not bash control-flow / variable-assignment / comment
 * plumbing inside a multi-line script. Only lines starting with a real
 * invocation (after stripping a merged `cd DIR &&` prefix and any leading
 * `VAR=value` env assignments) count as "gates" worth diffing; `if`, `fi`,
 * `files=(...)`, bare `echo`, etc. are glue, not tests. */
const KNOWN_CMD =
  /^(bash|node|npx|pnpm|go|cargo|python3?|ruby|bundle|zig|gradle|rake|lake|git|curl|tsx|sh|\$\w+)\b|^[\w./-]+\.sh\b/;

function stripEnvPrefix(line: string): string {
  let s = line;
  let m: RegExpExecArray | null;
  while ((m = /^[A-Z][A-Z0-9_]*=(?:"[^"]*"|\S*)\s+(.*)$/.exec(s))) {
    s = m[1]!;
  }
  return s;
}

function isCandidateCommand(line: string): boolean {
  if (SETUP_EXCLUDE.test(line)) return false;
  const afterCd = line.replace(/^cd \S+ && /, '');
  return KNOWN_CMD.test(stripEnvPrefix(afterCd));
}

/** Recursively expand a package.json script body, inlining every `pnpm run
 * <name>` reference it contains (same technique as the sibling
 * tests/ci-covers-root-tests.test.ts `expandScript`). */
function expandScript(name: string, scripts: Record<string, string>, seen = new Set<string>()): string {
  if (seen.has(name)) return '';
  seen.add(name);
  const body = scripts[name];
  if (body === undefined) return '';
  let out = body + '\n';
  for (const m of body.matchAll(/pnpm run ([A-Za-z0-9:_-]+)/g)) {
    out += expandScript(m[1]!, scripts, seen);
  }
  return out;
}

/** Whole jobs mirrored by a wrapper script `test:ci` already calls, matched
 * by name/semantics rather than literal per-line text — see the module
 * comment's `covered-by-wrapper` / `needs-opt-in` categories. */
const JOB_EXPLANATIONS: Record<string, string> = {
  'runar-verification':
    'covered-by-wrapper: mirrored by scripts/lean-verify.sh (RUNAR_LEAN_STRICT=1 pnpm run lean:verify), ' +
    'kept in sync with this job by name (binaries/scripts/build-targets, not literal text) by ' +
    'tests/f174-lean-verify-mirrors-ci.test.ts.',
  integration:
    'covered-by-wrapper: mirrored by integration/run-all.sh (RUNAR_INTEGRATION_STRICT=1 pnpm run ' +
    "integration:all). Each per-tier command matches run-all.sh's by flags/semantics, not literal " +
    "path text, because run-all.sh does its own `cd <tier>` from inside integration/ while this " +
    'job cds from the repo root (e.g. `cd integration/go && go test -tags integration -v -timeout ' +
    '1800s` here vs. `(cd go && go test -tags integration -v -timeout 1800s)` there) — verified by ' +
    'reading integration/run-all.sh against every per-tier step in this job.',
  'integration-teranode':
    'needs-opt-in: `if: github.event_name == \'workflow_dispatch\' && inputs.run_teranode` — never ' +
    'part of a default push/PR/merge_group run, so "green here -> green CI" never implied it.',
};

const ciText = read('.github/workflows/ci.yml');
const allJobs = parseJobs(ciText);

interface Candidate {
  job: string;
  line: string;
}

function buildCiCandidates(jobs: RawJob[]): Candidate[] {
  const out: Candidate[] = [];
  for (const job of jobs) {
    if (job.id in JOB_EXPLANATIONS) continue;
    for (const stepLines of splitSteps(job.lines)) {
      const runLines = extractRunLines(stepLines);
      if (!runLines) continue;
      const wd = extractField(stepLines, 'working-directory');
      let merged = mergeCd(runLines);
      if (wd) merged = merged.map((l) => `cd ${wd} && ${l}`);
      for (const l of merged) {
        if (!isCandidateCommand(l)) continue;
        out.push({ job: job.id, line: normalize(l) });
      }
    }
  }
  return out;
}

function buildLocalLines(): Set<string> {
  const pkg = JSON.parse(read('package.json')) as { scripts: Record<string, string> };
  const expanded = expandScript('test:ci', pkg.scripts);
  const out: string[] = [];
  for (const rawLine of expanded.split('\n').map((s) => s.trim()).filter(Boolean)) {
    out.push(...mergeCd(rawLine.split('&&').map((s) => s.trim()).filter(Boolean)));
  }
  return new Set(out.map(normalize));
}

const ciCandidates = buildCiCandidates(allJobs);
const localLines = buildLocalLines();

function isCoveredLocally(line: string): boolean {
  if (localLines.has(line)) return true;
  if (dirContainsFile(localLines, line)) return true;
  const alias = pathJoinedAlias(line);
  if (alias && (localLines.has(alias) || dirContainsFile(localLines, alias))) return true;
  return false;
}

/**
 * The measured gap: every ci.yml run-step command (job not in
 * JOB_EXPLANATIONS) with no exact, directory-prefix, or path-style
 * equivalent in `pnpm run test:ci`'s expansion. Formatted "<job> :: <cmd>"
 * so a job rename shows up as a diff instead of silently re-keying.
 *
 * Grouped by category (see module comment); `addable-locally` is the
 * follow-up candidate — none of these need a merge-base, a network fetch,
 * or a running node, they are just never wired into any `pnpm run` chain.
 */
const EXPECTED_UNCOVERED: string[] = [
  // --- addable-locally --------------------------------------------------
  'lint-no-silent-skips :: bash scripts/bump-version.sh --check',
  'golden-provenance-gate :: node conformance/scripts/check-golden-provenance.mjs --self-test',
  'go-only-crypto-vectors :: node conformance/scripts/check-bn254-pairing-invariants.mjs',
  'go-only-crypto-vectors :: node conformance/scripts/check-bn254-pairing-invariants.mjs --self-test',
  'go-only-crypto-vectors :: tests/generate-vectors/verify-reproducible.sh',
  'wire-format-must-move-golden :: pnpm run wire-format-audit:self-test',
  'sdk-envelope-fixtures :: cd conformance && npx tsx sdk-envelope/validate-fixtures.ts',
  'sdk-bip143-fixtures :: cd conformance && npx tsx sdk-bip143/generate-fixtures.ts --check',
  'ts-compiler :: cd compilers/rust && cargo build --release',
  'ts-compiler :: cd compilers/go && go build ./...',
  'ts-compiler :: cd compilers/go && go build -o runar-go .',
  'ts-compiler :: cd compilers/zig && zig build -Doptimize=ReleaseSafe',
  'ts-compiler :: cd compilers/java && gradle jar --no-daemon',
  'ts-compiler :: cd conformance && npx tsx fuzz-regressions/replay.ts',
  'ts-compiler :: cd conformance && npx tsx fuzz-regressions/replay.ts --check-no-deletions --base origin/main',
  'go-compiler :: cd compilers/go && go build ./...',
  'go-compiler :: cd compilers/go && go build -o runar-go .',
  'go-compiler :: cd compilers/go && go test -race -timeout 10m .',
  'go-compiler :: cd compilers/go && go test -race -timeout 10m ./frontend ./ir',
  'go-compiler :: cd compilers/go && go test -race -timeout 20m ./compiler',
  'go-compiler :: cd compilers/go && go test -timeout 20m ./codegen',
  'rust-compiler :: cd compilers/rust && cargo build --release',
  'rust-compiler :: cd compilers/rust && cargo test',
  'python-compiler :: cd compilers/go && go build -o runar-go .',
  'python-compiler :: cd compilers/python && PYTHONPATH=../../packages/runar-py python3 -m pytest tests -v',
  'zig-compiler :: cd compilers/go && go build -o runar-go .',
  'zig-compiler :: cd compilers/zig && zig build conformance',
  'zig-compiler :: cd compilers/zig && zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-gnu -Dcpu=baseline',
  'ruby-compiler :: cd compilers/go && go build -o runar-go .',
  'ruby-compiler :: cd compilers/ruby && bundle exec rake test',
  'go-sdk :: cd packages/runar-go && go test ./...',
  'rust-sdk :: cd packages/runar-rs && cargo test',
  'python-sdk :: cd packages/runar-py && python3 -m pytest',
  'ruby-sdk :: cd packages/runar-rb && bundle exec rspec',
  'ruby-sdk :: cd examples/ruby && bundle install',
  'ruby-sdk :: cd examples/ruby && bundle exec rspec **/*_spec.rb',
  'java-sdk :: cd packages/runar-java && gradle test --no-daemon',
  'java-sdk :: cd conformance/sdk-output/tools/java-driver && gradle fatJar --no-daemon',
  'conformance :: pnpm run conformance:typecheck',
  'conformance :: npx vitest run conformance/anf-scope.test.ts conformance/corpus-completeness.test.ts conformance/go-only-executing-coverage.test.ts conformance/fixture-count-doc.test.ts conformance/split-stack-desync.test.ts conformance/ci-predicate-sweep.test.ts conformance/codepart-pin conformance/dce conformance/source-map conformance/subtype-parity conformance/sdk-vertical conformance/sdk-call conformance/sdk-output/runner/sdk-runner-refusal-build-isolation.test.ts conformance/sdk-output/runner/sdk-output-coverage-audit.test.ts conformance/runner/__tests__ conformance/anf-interpreter/num2bin-engine-parity.test.ts conformance/anf-interpreter/driver-gate.test.ts conformance/wire-primitives.test.ts conformance/analyzer/__tests__ conformance/ir-roundtrip conformance/fuzz-regressions',
  'conformance :: cd conformance && npx vitest run negatives',
  'conformance :: cd conformance && npx vitest run go-only-parity',
  'conformance :: cd conformance && npx vitest run closed-findings',
  'conformance :: cd conformance && npx vitest run preimage-binding',
  'conformance :: cd conformance && npx vitest run witnesses',
  'conformance :: npx vitest run conformance/mutation',
  'conformance :: npx tsx conformance/analyzer/run.ts',
  'conformance :: npx tsx conformance/scripts/check-derived-artifacts.ts --check',
  'conformance-anf-parity :: cd conformance/anf-interpreter/drivers/rust && cargo build --release',
  'conformance-anf-parity :: cd conformance/anf-interpreter/drivers/java && gradle fatJar --no-daemon',
  'conformance-anf-parity :: cd conformance/anf-interpreter/drivers/zig && zig build -Doptimize=ReleaseSafe',
  'decompiler-roundtrip :: pnpm --filter runar-decompiler run coverage',
  'decompiler-roundtrip :: pnpm run decompiler:fingerprints:check',
  'decompiler-roundtrip :: pnpm run decompiler:templates:check',
  'sdk-conformance :: cd conformance/sdk-output/tools/rs-sdk-tool && cargo build --release',
  'sdk-conformance :: cd conformance/sdk-output/tools/zig-sdk-tool && zig build -Doptimize=ReleaseFast',
  'sdk-conformance :: cd conformance/sdk-output/tools/java-driver && gradle fatJar --no-daemon',
  'sdk-conformance :: cd conformance && npx tsx sdk-output/generate-inputs.ts --check',
  'sdk-conformance :: cd conformance && npx tsx sdk-vertical/runner/vertical-runner.ts',
  'script-execution :: cd conformance && go test -v -timeout 1200s .',
  // --- needs-merge-base (the gate diffs <base>...HEAD; no base outside a
  //     PR/push/merge_group event) ----------------------------------------
  'golden-provenance-gate :: GOLDEN_GATE_BASE="${base}" node conformance/scripts/check-golden-provenance.mjs',
  'wire-format-must-move-golden :: WIRE_FORMAT_GATE_BASE="${base}" pnpm run wire-format-audit',
  // --- transitive-via-turbo (turbo.json: `test`/`typecheck` dependsOn
  //     `build`; the named package's own `test`/`typecheck` script IS this
  //     command — verified against that package's package.json) ----------
  'ts-compiler :: pnpm run build',
  'ts-compiler :: npx vitest run packages/runar-testing/src/__tests__/fold-equivalence.test.ts',
  'conformance :: pnpm run build',
  'conformance-anf-parity :: pnpm run build',
  'decompiler-roundtrip :: pnpm run build',
  'decompiler-roundtrip :: pnpm --filter runar-decompiler run typecheck',
  'decompiler-roundtrip :: pnpm --filter runar-decompiler run test',
  'sdk-conformance :: pnpm run build',
  'script-execution :: pnpm run build',
  // --- transitive-via-script (a sibling command in the same job already
  //     performs this as a side effect) -----------------------------------
  'java-compiler :: cd compilers/java && gradle build --no-daemon',
];

describe('N-283: pnpm test:ci vs .github/workflows/ci.yml — the measured drift', () => {
  it('parses a non-trivial number of ci.yml jobs (anti-vacuity)', () => {
    expect(allJobs.length).toBeGreaterThan(20);
    expect(allJobs.map((j) => j.id)).toContain('conformance');
  });

  it('every JOB_EXPLANATIONS entry names a job that still exists in ci.yml', () => {
    const ids = new Set(allJobs.map((j) => j.id));
    const missing = Object.keys(JOB_EXPLANATIONS).filter((id) => !ids.has(id));
    expect(missing, 'a covered-by-wrapper/needs-opt-in job was renamed or removed').toEqual([]);
  });

  it('extracts a non-trivial number of candidate CI commands (anti-vacuity)', () => {
    expect(ciCandidates.length).toBeGreaterThan(60);
  });

  it('expands a non-trivial `pnpm run test:ci` command set (anti-vacuity)', () => {
    expect(localLines.size).toBeGreaterThan(50);
    expect(localLines.has('bash scripts/lint-no-silent-skips.sh')).toBe(true);
  });

  it('the measured set of ci.yml commands with no local equivalent matches the pinned, categorized list', () => {
    const actual = [...new Set(ciCandidates.filter((c) => !isCoveredLocally(c.line)).map((c) => `${c.job} :: ${c.line}`))].sort();
    const expected = [...EXPECTED_UNCOVERED].sort();

    const newlyUncovered = actual.filter((a) => !expected.includes(a));
    const noLongerUncovered = expected.filter((e) => !actual.includes(e));

    expect(
      newlyUncovered,
      'ci.yml runs something pnpm test:ci does not, and it is not in the pinned list above. ' +
        'Either wire it into test:ci (if it needs no merge-base/network/service), or add it to ' +
        'EXPECTED_UNCOVERED with a category and a one-line reason.',
    ).toEqual([]);
    expect(
      noLongerUncovered,
      'these pinned gaps no longer show up as uncovered -- either test:ci now runs them (delete the ' +
        'line, and update README.md/CONTRIBUTING.md if the count they cite changed) or the parser ' +
        'regressed (false "covered").',
    ).toEqual([]);
  });

  it('EXPECTED_UNCOVERED has no duplicate entries', () => {
    const seen = new Set<string>();
    const dupes = EXPECTED_UNCOVERED.filter((e) => (seen.has(e) ? true : (seen.add(e), false)));
    expect(dupes).toEqual([]);
  });

  it('the reverse direction: pnpm test:ci runs a wallet-client family that ci.yml never names', () => {
    // The one direction where test:ci runs something CI runs nothing like:
    // seven per-tier `wallet-client:*` commands (env-gated — RUNAR_WALLET_ENDPOINT
    // unset means each skips clean, so this is harmless, not a false-green risk,
    // but it IS local work with zero CI counterpart).
    const pkg = JSON.parse(read('package.json')) as { scripts: Record<string, string> };
    expect(pkg.scripts['wallet-client:all'], 'package.json: wallet-client:all script not found').toBeTruthy();
    expect(
      ciText,
      'ci.yml now mentions "wallet-client" -- update this test (and the module comment) to say which ' +
        'direction the gap closed in, instead of leaving a stale "CI never runs this" claim.',
    ).not.toMatch(/wallet.?client/i);
  });

  it('README.md / CONTRIBUTING.md no longer promise an unconditional mirror and point at this test', () => {
    const readme = read('README.md');
    const contributing = read('CONTRIBUTING.md');

    // The defect: README.md's `pnpm test:ci` row said "The contract is:
    // green here -> green CI" with nothing qualifying it, and
    // CONTRIBUTING.md's table said "Mirrors CI" -- both unconditional, and
    // both false given the ~72-command gap measured above. Both now have to
    // name this test as the place the real (pinned, categorized) gap lives,
    // instead of repeating the unconditional claim.
    expect(
      readme,
      'README.md no longer names tests/n283-test-ci-mirrors-ci-contract.test.ts next to the ' +
        '`pnpm test:ci` row -- it should point there instead of (or alongside) any "mirrors CI" claim.',
    ).toMatch(/n283-test-ci-mirrors-ci-contract\.test\.ts/);
    expect(
      contributing,
      'CONTRIBUTING.md no longer names tests/n283-test-ci-mirrors-ci-contract.test.ts next to its ' +
        '`pnpm test:ci` row.',
    ).toMatch(/n283-test-ci-mirrors-ci-contract\.test\.ts/);

    expect(
      readme,
      'README.md still claims the unconditional "green here -> green CI" contract this test disproves.',
    ).not.toMatch(/green here\s*(?:->|→)\s*green CI/i);
  });
});
