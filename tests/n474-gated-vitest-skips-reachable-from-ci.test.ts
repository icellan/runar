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
 *   wallet    `RUNAR_WALLET_ENDPOINT` (a BRC-100 wallet). N-480: CI provides
 *             one — integration/mock-wallet/mock-wallet.sh starts an in-repo
 *             BRC-100 test wallet in the integration job. Some CI step must
 *             reach the file with RUNAR_WALLET_ENDPOINT set (step or job env)
 *             AFTER a step that ran `mock-wallet.sh start`. No strict-mode
 *             half is needed: the gate IS the env var, so with it set a dead
 *             wallet is a connection failure, not a skip. The same rule is
 *             held for the six non-vitest wallet-client tests (Go, Rust,
 *             Python, Zig, Ruby, Java), pinned with their CI commands below.
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
 * conditions above; every wallet-gated test, in all seven tiers, runs in a
 * CI step with the wallet started and RUNAR_WALLET_ENDPOINT set.
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

/**
 * `src` with comments and the bodies of string / template literals blanked to
 * spaces (same length, newlines kept), so text that merely MENTIONS
 * `.skipIf(` — this file's own prose and fixtures — is not mistaken for a call.
 */
function maskNonCode(src: string): string {
  const out = src.split('');
  const blank = (from: number, to: number) => {
    for (let k = from; k < to; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    if (c === '/' && src[i + 1] === '/') {
      let j = i;
      while (j < src.length && src[j] !== '\n') j++;
      blank(i, j);
      i = j;
    } else if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      const j = end < 0 ? src.length : end + 2;
      blank(i, j);
      i = j;
    } else if (c === "'" || c === '"' || c === '`') {
      let j = i + 1;
      while (j < src.length && src[j] !== c) {
        if (src[j] === '\\') j++;
        else if (c !== '`' && src[j] === '\n') break;
        j++;
      }
      blank(i + 1, j);
      i = j + 1;
    } else {
      i++;
    }
  }
  return out.join('');
}

/** The text between the parens of every `.skipIf(` / `.runIf(` call. */
function gatePredicates(src: string): string[] {
  const code = maskNonCode(src);
  const out: string[] = [];
  const re = /\.(skipIf|runIf)\(/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(code)) !== null) {
    let depth = 1;
    let i = m.index + m[0].length;
    const start = i;
    for (; i < code.length && depth > 0; i++) {
      if (code[i] === '(') depth++;
      else if (code[i] === ')') depth--;
    }
    // Slice the ORIGINAL text: the predicate's own string literals matter to classify().
    out.push(src.slice(start, i - 1).trim());
  }
  return out;
}

type GateClass = 'slow' | 'regtest' | 'wallet' | 'toolchain';

function classify(pred: string): GateClass | null {
  if (/\brunSlowTests\b/.test(pred)) return 'slow';
  if (/\bnodeUp\b/.test(pred)) return 'regtest';
  if (/\bENDPOINT\b/.test(pred)) return 'wallet';
  if (
    /\bisDriverAvailable\(|\bhas(Go|Rust|Python)\b|\w+(BinaryPath|ScriptPath|JarPath)\b|\b\w*[bB]inary\s*===\s*null\b/.test(
      pred,
    )
  ) {
    return 'toolchain';
  }
  return null;
}

/**
 * N-480: the wallet-gated tests outside vitest (one per non-TS tier), each with
 * the exact CI command that must run it. Their gates are not `.skipIf` calls
 * (t.Skip, #[ignore], pytest.mark.skipif, SkipZigTest, rspec `skip`,
 * @EnabledIfEnvironmentVariable), so this guard cannot discover them; it pins
 * them instead, and checks each file still reads RUNAR_WALLET_ENDPOINT.
 */
const NATIVE_WALLET_TESTS: { file: string; command: string; wiredBy?: { file: string; text: string } }[] = [
  {
    file: 'packages/runar-go/sdk_wallet_client_integration_test.go',
    command: 'cd packages/runar-go && go test -run TestWalletClient_LiveEndpoint_RoundTrip -v',
  },
  {
    file: 'packages/runar-rs/tests/wallet_client_integration.rs',
    command: 'cd packages/runar-rs && cargo test --test wallet_client_integration -- --ignored',
  },
  {
    file: 'packages/runar-py/tests/test_wallet_client_integration.py',
    command: 'cd packages/runar-py && python3 -m pytest tests/test_wallet_client_integration.py -v',
  },
  {
    file: 'packages/runar-zig/src/sdk_wallet_client_integration_test.zig',
    command: 'cd packages/runar-zig && zig build test',
    // Zig compiles only the test files root.zig imports; this one was orphaned (N-480 found
    // `zig build test` with the endpoint set never ran it).
    wiredBy: { file: 'packages/runar-zig/src/root.zig', text: '_ = @import("sdk_wallet_client_integration_test.zig");' },
  },
  // Reached by the integration job's whole-suite Ruby step (the job env sets the endpoint).
  { file: 'integration/ruby/spec/wallet_client_spec.rb', command: 'cd integration/ruby && bundle exec rspec --format documentation' },
  {
    file: 'packages/runar-java/src/test/java/runar/lang/sdk/WalletClientIntegrationTest.java',
    command: 'cd packages/runar-java && ./gradlew test --tests runar.lang.sdk.WalletClientIntegrationTest --no-daemon',
  },
];

/** Is `step` (index `stepIdx` of `job`) run with a BRC-100 wallet up and RUNAR_WALLET_ENDPOINT set? */
function walletProvisioned(job: Job, stepIdx: number, step: Step): boolean {
  const started = job.steps
    .slice(0, stepIdx)
    .some((s) => s.commands.some((c) => /mock-wallet\.sh\s+start\b/.test(c)));
  const endpoint = step.env.RUNAR_WALLET_ENDPOINT ?? job.env.RUNAR_WALLET_ENDPOINT ?? '';
  return started && endpoint.trim() !== '';
}

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

  // N-480. Proves: every vitest file gated on RUNAR_WALLET_ENDPOINT, and each pinned
  // native-tier wallet test, is run by a ci.yml step that comes after `mock-wallet.sh start`
  // in the same job and has RUNAR_WALLET_ENDPOINT set — so none of the seven is a skip in CI.
  // Does not prove: that they pass (the CI run shows that; N-480's log records one local
  // passing run of each against the mock), nor that the mock is a full BRC-100 wallet — it
  // serves exactly the two calls these tests make (getPublicKey, listOutputs).
  it('every wallet-gated test runs after `mock-wallet.sh start` with RUNAR_WALLET_ENDPOINT set', () => {
    const wallet = byClass.get('wallet') ?? [];
    expect(wallet).toContain('packages/runar-sdk/src/__tests__/wallet-client.spec.ts');
    const problems: string[] = [];
    for (const f of wallet) {
      const ok = reachingSteps(jobs, f, pkgs).some(({ job, stepIdx, step }) => walletProvisioned(job, stepIdx, step));
      if (!ok) problems.push(`${f}: no CI step runs it after \`mock-wallet.sh start\` with RUNAR_WALLET_ENDPOINT set`);
    }
    for (const { file, command, wiredBy } of NATIVE_WALLET_TESTS) {
      // A whole line equal to the import (so a commented-out `// _ = @import(...)` does not count).
      const wired = !wiredBy || readFileSync(join(ROOT, wiredBy.file), 'utf8').split('\n').some((l) => l.trim() === wiredBy.text);
      if (!wired && wiredBy) {
        problems.push(`${file}: not compiled into the suite \`${command}\` runs (${wiredBy.file} lacks \`${wiredBy.text}\`)`);
      }
      if (!existsSync(join(ROOT, file))) {
        problems.push(`${file}: pinned wallet test no longer exists`);
        continue;
      }
      if (!readFileSync(join(ROOT, file), 'utf8').includes('RUNAR_WALLET_ENDPOINT')) {
        problems.push(`${file}: no longer gated on RUNAR_WALLET_ENDPOINT — re-pin it`);
      }
      const ok = jobs.some((job) =>
        job.steps.some((step, stepIdx) => step.commands.includes(command) && walletProvisioned(job, stepIdx, step)),
      );
      if (!ok) problems.push(`${file}: no CI step runs \`${command}\` after \`mock-wallet.sh start\` with RUNAR_WALLET_ENDPOINT set`);
    }
    expect(problems).toEqual([]);
  });

  // Proves: the scanner reads call syntax, not prose — a `.skipIf(` inside a comment or
  // string/template literal is ignored (so this file does not flag itself once tracked), while
  // a real unclassified `.skipIf(process.env.X)` is still reported and a real classified one
  // still classifies. Does not prove: handling of regex literals or `${}` expressions inside
  // templates; the in-memory sources below stand in for tracked files (no decoy files exist).
  it('gatePredicates ignores prose and literals but still reports genuine gates', () => {
    // Built with call() so this file's own text never contains a literal gate call (the
    // skip-inventory audit scans text, exactly like the scanner under test).
    const call = (kind: string, pred: string) => `.${kind}(${pred})`;
    const prose = [
      `// it${call('skipIf', 'process.env.X')}('a', () => {})`,
      `/* describe${call('runIf', 'foo')}("b", () => {}) */`,
      `const a = 'x${call('skipIf', 'process.env.Y')}';`,
      'const b = `y' + call('runIf', '${pred}') + '`;',
    ].join('\n');
    expect(gatePredicates(prose)).toEqual([]);

    const real = `describe${call('skipIf', "process.env.UNKNOWN_GATE !== '1'")}('c', () => {});`;
    expect(gatePredicates(real)).toEqual(["process.env.UNKNOWN_GATE !== '1'"]);
    expect(classify(gatePredicates(real)[0]!)).toBeNull();

    const gated = `it${call('skipIf', '!nodeUp')}('d', () => {}); // it${call('skipIf', 'foo')}`;
    expect(gatePredicates(gated).map(classify)).toEqual(['regtest']);
  });
});
