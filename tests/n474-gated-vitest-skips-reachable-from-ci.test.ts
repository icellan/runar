/**
 * N-474 — every env-gated vitest skip must be executed, with its gate set,
 * by some CI step.
 *
 * checkpoint-57's whole-repo `npx vitest run` reported 150 skipped tests. Each
 * one was documented in docs/test-skips.md, and documented is not executed: a
 * suite gated on `nodeUp` that no CI job ever runs next to a regtest
 * node is coverage that exists only on the machine of whoever wrote it. That
 * was the state of `multi-contract-call.regtest.test.ts` — the only CI step
 * that reached it (ts-compiler's `pnpm run test`) has no node, so it skipped
 * there too, every run.
 *
 * This guard classifies every `.skipIf(...)` / `.runIf(...)` predicate in every
 * tracked vitest file and holds each class to what "executed with the gate
 * set" means for it:
 *
 *   slow      `runSlowTests` (packages/runar-testing/src/test-env.ts: true when
 *             CI=true / GITHUB_ACTIONS=true, or RUN_SLOW_TESTS=1). GitHub
 *             Actions sets both CI vars on every step, and turbo forwards them
 *             to each package's `vitest run` (measured for N-474: under
 *             `CI=true GITHUB_ACTIONS=true turbo run test` the gated cases run).
 *             So: some CI step must reach the file. (N-474 measured every
 *             file that used this gate at 3-26 s and removed the gate, so the
 *             class is empty today; it stays so a new one is held to CI.)
 *   regtest   `nodeUp` (a live BSV regtest node answered `getblockcount`). Some
 *             CI step must reach the file in a job that starts the node
 *             (`regtest.sh start`) in an EARLIER step, and must set
 *             RUNAR_INTEGRATION_STRICT=1 — which the file must honour by
 *             failing, not skipping, when no node answers. Without the strict
 *             half a dead node turns the step back into a green skip.
 *   external  `RUNAR_WALLET_ENDPOINT` (a live BRC-100 wallet). No CI job has
 *             one, in any of the seven tiers. Pinned EXACTLY below: a new file
 *             gated on an external service fails here until someone decides
 *             how it gets run; removing one fails until the pin is lowered.
 *   toolchain a peer compiler / SDK driver binary is absent. CI builds every
 *             tier and sets RUNAR_REQUIRE_ALL_COMPILERS / strict driver gates
 *             for those suites; they are not env-gated skips and are not
 *             counted by this item.
 *
 * A predicate matching none of these fails the guard: a new gate must be
 * classified (and, if it is env-shaped, wired into CI) before it can land.
 *
 * Proves: for every slow/regtest-gated vitest file, the ci.yml text contains a
 * step that reaches it (a `vitest run` naming it or an ancestor dir, or a
 * whole-workspace `pnpm run test` / `pnpm --filter <pkg> run test` for a
 * workspace package whose test script is a bare `vitest run`) under the
 * conditions above; the external-service set is exactly the pinned one.
 * Does NOT prove the reached tests pass in CI — that is what the CI run is
 * for; N-474's logs record one local passing run of each with the gate set.
 * Does not parse YAML in general: it understands this repo's ci.yml layout
 * (jobs at indent 2, steps at indent 6, step fields at indent 8) and its floor
 * assertions fail loudly if that layout stops parsing.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CI_YML = join(ROOT, '.github', 'workflows', 'ci.yml');

// ---------------------------------------------------------------- the files

function trackedVitestFiles(): string[] {
  const out = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return out
    .split('\n')
    .filter((f) => /\.(test|spec)\.(ts|mts)$/.test(f))
    .filter((f) => !f.includes('node_modules/') && !f.includes('.runar.'))
    .sort();
}

/** The text between the parens of every `.skipIf(` / `.runIf(` call. */
function gatePredicates(src: string): string[] {
  const out: string[] = [];
  const re = /\.(skipIf|runIf)\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    let depth = 1;
    let i = m.index + m[0].length;
    const start = i;
    for (; i < src.length && depth > 0; i++) {
      if (src[i] === '(') depth++;
      else if (src[i] === ')') depth--;
    }
    out.push(src.slice(start, i - 1).trim());
  }
  return out;
}

type GateClass = 'slow' | 'regtest' | 'external' | 'toolchain';

function classify(pred: string): GateClass | null {
  if (/\brunSlowTests\b/.test(pred)) return 'slow';
  if (/\bnodeUp\b/.test(pred)) return 'regtest';
  if (/\bENDPOINT\b/.test(pred)) return 'external';
  if (
    /\bisDriverAvailable\(|\bhas(Go|Rust|Python)\b|\w+(BinaryPath|ScriptPath|JarPath)\b|\b\w*[bB]inary\s*===\s*null\b/.test(
      pred,
    )
  ) {
    return 'toolchain';
  }
  return null;
}

/** External-service gates with no CI provision. Exact pin — see header. */
const EXTERNAL_SERVICE_GATED = ['packages/runar-sdk/src/__tests__/wallet-client.spec.ts'];

// ---------------------------------------------------------------- ci.yml

interface Step {
  /** run: lines, `cd DIR` prefixes merged in, comments dropped. */
  commands: string[];
  env: Record<string, string>;
}
interface Job {
  id: string;
  env: Record<string, string>;
  steps: Step[];
}

const indentOf = (l: string) => l.match(/^ */)![0].length;

function parseEnv(lines: string[], headerIdx: number, headerIndent: number): Record<string, string> {
  const env: Record<string, string> = {};
  for (let i = headerIdx + 1; i < lines.length; i++) {
    const l = lines[i]!;
    if (l.trim() === '' || /^\s*#/.test(l)) continue;
    if (indentOf(l) <= headerIndent) break;
    const m = /^\s*([A-Za-z0-9_]+):\s*(.*)$/.exec(l);
    if (m) env[m[1]!] = m[2]!.replace(/^['"]|['"]$/g, '');
  }
  return env;
}

function parseCi(text: string): Job[] {
  const lines = text.split('\n');
  const jobsIdx = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  const jobs: Job[] = [];
  let job: Job | null = null;
  let step: string[] | null = null;
  const flush = () => {
    if (job && step) job.steps.push(parseStep(step));
    step = null;
  };
  for (let i = jobsIdx + 1; i < lines.length; i++) {
    const l = lines[i]!;
    if (l.trim() === '' || /^\s*#/.test(l)) {
      if (step) step.push(l);
      continue;
    }
    const ind = indentOf(l);
    if (ind === 0) break;
    const jm = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(l);
    if (jm) {
      flush();
      job = { id: jm[1]!, env: {}, steps: [] };
      jobs.push(job);
      continue;
    }
    if (!job) continue;
    if (ind === 4 && /^ {4}env:\s*$/.test(l)) {
      job.env = parseEnv(lines, i, 4);
      continue;
    }
    if (ind === 6 && l.slice(6).startsWith('- ')) {
      flush();
      step = ['        ' + l.slice(8)];
      continue;
    }
    if (ind <= 4) {
      flush();
      continue;
    }
    if (step) step.push(l);
  }
  flush();
  return jobs;
}

function parseStep(stepLines: string[]): Step {
  const envIdx = stepLines.findIndex((l) => /^ {8}env:\s*$/.test(l));
  const env = envIdx >= 0 ? parseEnv(stepLines, envIdx, 8) : {};
  const runIdx = stepLines.findIndex((l) => /^ {8}run:/.test(l));
  if (runIdx < 0) return { commands: [], env };
  const rest = /^ {8}run:\s*(.*)$/.exec(stepLines[runIdx]!)![1]!.trim();
  let raw: string[];
  if (rest === '|' || rest === '|-' || rest === '>' || rest === '>-') {
    raw = [];
    for (let i = runIdx + 1; i < stepLines.length; i++) {
      const l = stepLines[i]!;
      if (l.trim() === '') continue;
      if (indentOf(l) <= 8) break;
      if (/^\s*#/.test(l)) continue;
      raw.push(l.trim());
    }
    if (rest.startsWith('>')) raw = [raw.join(' ')];
  } else {
    raw = [rest];
  }
  // A bare `cd DIR` line applies to the lines after it, as in a shell.
  const commands: string[] = [];
  let cd = '';
  for (const r of raw) {
    const bare = /^cd\s+(\S+)\s*$/.exec(r);
    if (bare) {
      cd = bare[1]!;
      continue;
    }
    commands.push(cd ? `cd ${cd} && ${r}` : r);
  }
  return { commands, env };
}

// ---------------------------------------------------------------- reach

/** Workspace packages whose `test` script is a bare `vitest run` (no path filter). */
function bareVitestPackages(): Map<string, string> {
  const out = new Map<string, string>(); // dir -> package name
  for (const f of execFileSync('git', ['ls-files', 'packages/*/package.json'], { cwd: ROOT, encoding: 'utf8' })
    .split('\n')
    .filter(Boolean)) {
    const pkg = JSON.parse(readFileSync(join(ROOT, f), 'utf8')) as { name?: string; scripts?: Record<string, string> };
    if (pkg.scripts?.test?.trim() === 'vitest run' && pkg.name) out.set(dirname(f), pkg.name);
  }
  return out;
}

/** Does `command` run the vitest file `file` (repo-relative)? */
function reaches(command: string, file: string, pkgs: Map<string, string>): boolean {
  const cdm = /^cd\s+(\S+)\s*&&\s*(.*)$/.exec(command);
  const cwd = cdm ? posix.normalize(cdm[1]!) : '.';
  const cmd = cdm ? cdm[2]! : command;

  // Whole-workspace turbo test from the repo root.
  if (cwd === '.' && /^(pnpm\s+(run\s+)?test|npx\s+turbo\s+run\s+test|turbo\s+run\s+test)\s*$/.test(cmd)) {
    for (const dir of pkgs.keys()) if (file.startsWith(dir + '/')) return true;
  }
  // `pnpm --filter <name> run test`.
  const fm = /^pnpm\s+--filter\s+(\S+)\s+(run\s+)?test\s*$/.exec(cmd);
  if (cwd === '.' && fm) {
    for (const [dir, name] of pkgs) if (name === fm[1] && file.startsWith(dir + '/')) return true;
  }
  // `npx vitest run [paths...]`, relative to cwd.
  const vm = /(?:^|&&\s*)(?:[A-Z_]+=\S+\s+)*npx\s+vitest\s+run\b([^&|;]*)/.exec(cmd);
  if (vm) {
    const args = vm[1]!.trim().split(/\s+/).filter((a) => a && !a.startsWith('-'));
    if (args.length === 0) return cwd === '.' || file.startsWith(cwd + '/');
    for (const a of args) {
      const p = posix.normalize(posix.join(cwd, a)).replace(/\/$/, '');
      if (file === p || file.startsWith(p + '/')) return true;
    }
  }
  return false;
}

interface Reach {
  job: Job;
  stepIdx: number;
  step: Step;
}

function reachingSteps(jobs: Job[], file: string, pkgs: Map<string, string>): Reach[] {
  const out: Reach[] = [];
  for (const job of jobs) {
    job.steps.forEach((step, stepIdx) => {
      if (step.commands.some((c) => reaches(c, file, pkgs))) out.push({ job, stepIdx, step });
    });
  }
  return out;
}

// ---------------------------------------------------------------- the guard

describe('N-474: every env-gated vitest skip is executed by CI with its gate set', () => {
  const files = trackedVitestFiles();
  const jobs = parseCi(readFileSync(CI_YML, 'utf8'));
  const pkgs = bareVitestPackages();

  const byClass = new Map<GateClass, string[]>();
  const unclassified: string[] = [];
  for (const f of files) {
    const src = readFileSync(join(ROOT, f), 'utf8');
    for (const pred of gatePredicates(src)) {
      const c = classify(pred);
      if (c === null) {
        unclassified.push(`${f}: .skipIf/.runIf(${pred})`);
        continue;
      }
      const list = byClass.get(c) ?? [];
      if (!list.includes(f)) list.push(f);
      byClass.set(c, list);
    }
  }

  it('parses the repo and ci.yml (anti-vacuity floors)', () => {
    expect(files.length).toBeGreaterThan(500);
    expect(jobs.length).toBeGreaterThan(15);
    expect(jobs.find((j) => j.id === 'ts-compiler')?.steps.length ?? 0).toBeGreaterThan(10);
    expect(jobs.find((j) => j.id === 'integration')?.env.RPC_URL).toBe('http://localhost:18332');
    expect(pkgs.has('packages/runar-testing')).toBe(true);
    // The reach model itself must see the two steps that carry the bulk of
    // vitest in CI, or every "reached" verdict below is vacuous.
    expect(reachingSteps(jobs, 'packages/runar-testing/src/__tests__/post-quantum-bounds.test.ts', pkgs).map((r) => r.job.id)).toContain('ts-compiler');
    expect(reachingSteps(jobs, 'examples/sol/sphincs-wallet/SPHINCSWallet.test.ts', pkgs).map((r) => r.job.id)).toContain('ts-compiler');
    expect(byClass.get('toolchain')?.length ?? 0).toBeGreaterThan(0);
  });

  it('every skipIf/runIf predicate belongs to a known gate class', () => {
    expect(
      unclassified,
      'classify each new gate in tests/n474-gated-vitest-skips-reachable-from-ci.test.ts — ' +
        'and if it is env-shaped, wire a CI step that runs it with the gate set',
    ).toEqual([]);
  });

  it('every runSlowTests-gated file is reached by a CI step (GitHub sets CI=true)', () => {
    const unreached = (byClass.get('slow') ?? []).filter((f) => reachingSteps(jobs, f, pkgs).length === 0);
    expect(unreached, 'slow-gated vitest files no CI step runs').toEqual([]);
  });

  it('every regtest-gated file runs after `regtest.sh start` with RUNAR_INTEGRATION_STRICT=1, and fails closed under it', () => {
    const regtest = byClass.get('regtest') ?? [];
    expect(regtest.length).toBeGreaterThan(0);
    const problems: string[] = [];
    for (const f of regtest) {
      const ok = reachingSteps(jobs, f, pkgs).some(({ job, stepIdx, step }) => {
        const nodeStarted = job.steps
          .slice(0, stepIdx)
          .some((s) => s.commands.some((c) => /regtest\.sh\s+start\b/.test(c)));
        const strict = (step.env.RUNAR_INTEGRATION_STRICT ?? job.env.RUNAR_INTEGRATION_STRICT) === '1';
        return nodeStarted && strict;
      });
      if (!ok) problems.push(`${f}: no CI step runs it after \`regtest.sh start\` with RUNAR_INTEGRATION_STRICT=1`);
      const src = readFileSync(join(ROOT, f), 'utf8');
      if (!/RUNAR_INTEGRATION_STRICT/.test(src)) {
        problems.push(`${f}: does not read RUNAR_INTEGRATION_STRICT, so a dead node is a green skip`);
      }
    }
    expect(problems).toEqual([]);
  });

  it('the external-service-gated set is exactly the pinned one (no CI provision exists)', () => {
    expect([...(byClass.get('external') ?? [])].sort()).toEqual([...EXTERNAL_SERVICE_GATED].sort());
    for (const f of EXTERNAL_SERVICE_GATED) expect(existsSync(join(ROOT, f))).toBe(true);
  });
});
