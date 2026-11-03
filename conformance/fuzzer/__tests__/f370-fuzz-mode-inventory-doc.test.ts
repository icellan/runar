/**
 * F-370 — the fuzzer README must enumerate every fuzz mode, where each one runs
 * in CI, and which language constructs each one does NOT generate.
 *
 * Before this, `conformance/fuzzer/README.md` had a mode table with an oracle
 * column but no per-mode "cannot generate" list and no CI placement, so the
 * partial-coverage facts (`--ir --hex` keeps `sourceLoc` but the ANF-depth
 * compare strips it; `--anf` never draws `if`/`loop`/the stateful-only kinds;
 * `--execute` is a single-tier oracle) lived only in code comments.
 *
 * PROVES (every assertion re-derives its expected set from the live source):
 *   - every mode flag `fuzzer/index.ts` dispatches on (`if (opts.<x>)` in
 *     `main()`) has a `### \`--flag\`` section in the README, with a
 *     "Cannot generate:" line;
 *   - every CLI flag `parseArgs` accepts is mentioned in the README;
 *   - every step in `fuzzer-nightly.yml` that invokes a fuzz driver has a row in
 *     the README CI table whose placement cell (PR only / non-PR / every
 *     trigger) matches the step's `if:` guard, and the ci.yml replay steps are
 *     listed;
 *   - the `--anf` section names exactly the ANF kinds the generator does not
 *     draw (complement of `AnfValue` in `anf-differential.ts` within
 *     `anf-ir.ts`), so adding a generated kind or an ANF kind reddens this test
 *     until the README is updated;
 *   - the code facts the README leans on still hold (sourceLoc stripped only in
 *     the non-hex compare; execute / tri-modal / spend-oracle spawn no tier
 *     process).
 * DOES NOT PROVE: that the prose "Cannot generate" lists are complete for the
 * generators' expression-level repertoire (only the ANF kind list is derived
 * mechanically), nor that the workflow steps pass.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const REPO = resolve(__dirname, '../../..');
const read = (rel: string) => readFileSync(resolve(REPO, rel), 'utf8');

const README = read('conformance/fuzzer/README.md');
const INDEX = read('conformance/fuzzer/index.ts');
const NIGHTLY = read('.github/workflows/fuzzer-nightly.yml');
const CI = read('.github/workflows/ci.yml');

/** Text of the `### \`--flag\`` section (up to the next `##`/`###` heading). */
function section(flag: string): string | undefined {
  const re = new RegExp('^###\\s+`' + flag.replace(/[-]/g, '\\-') + '`[^\\n]*\\n([\\s\\S]*?)(?=^#{2,3}\\s|$(?![\\s\\S]))', 'm');
  return re.exec(README)?.[1];
}

/** `case '--x':\n opts.prop = true;` pairs from parseArgs. */
function flagToProp(): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of INDEX.matchAll(/case '(--[a-z-]+)':\s*\n\s*opts\.(\w+) = true;/g)) {
    out.set(m[1]!, m[2]!);
  }
  return out;
}

/** Mode flags: boolean flags whose option is branched on with `if (opts.x)` in main(). */
function modeFlags(): string[] {
  const main = INDEX.slice(INDEX.indexOf('async function main()'));
  const modes: string[] = [];
  for (const [flag, prop] of flagToProp()) {
    if (new RegExp(`\\n  if \\(opts\\.${prop}\\) \\{`).test(main)) modes.push(flag);
  }
  return modes;
}

interface Step { job: string; name: string; body: string; placement: string }

function workflowSteps(yml: string): Step[] {
  const steps: Step[] = [];
  const jobsAt = yml.indexOf('\njobs:');
  const jobRe = /^  ([a-z0-9-]+):\s*$/gm;
  const body = yml.slice(jobsAt);
  const jobStarts: Array<{ id: string; at: number }> = [];
  for (const m of body.matchAll(jobRe)) jobStarts.push({ id: m[1]!, at: m.index! });
  jobStarts.forEach((j, i) => {
    const chunk = body.slice(j.at, jobStarts[i + 1]?.at ?? body.length);
    for (const s of chunk.split(/\n      - name: /).slice(1)) {
      const name = s.split('\n')[0]!.trim();
      const ifLine = /\n        if: (.+)/.exec(s)?.[1] ?? '';
      const placement = /event_name == 'pull_request'/.test(ifLine)
        ? 'PR only'
        : /event_name != 'pull_request'/.test(ifLine)
          ? 'non-PR'
          : 'every trigger';
      steps.push({ job: j.id, name, body: s, placement });
    }
  });
  return steps;
}

const DRIVER_RE = /tsx fuzzer\/(index|metamorphic-fuzz|canonical-java-gate)\.ts/;

describe('F-370 fuzz mode inventory is documented', () => {
  it('derives a non-trivial mode set from index.ts (anti-vacuity)', () => {
    const modes = modeFlags();
    for (const expected of ['--ir', '--anf', '--canonical', '--execute', '--tri-modal', '--spend-oracle', '--replay']) {
      expect(modes, `mode flag ${expected} not derived from index.ts`).toContain(expected);
    }
  });

  it('README has a section with a "Cannot generate:" line for every mode flag', () => {
    const missing: string[] = [];
    for (const flag of modeFlags()) {
      const s = section(flag);
      if (s === undefined) missing.push(`${flag}: no "### \`${flag}\`" section`);
      else if (!/^\*\*Cannot generate:\*\*\s+\S/m.test(s)) missing.push(`${flag}: no "**Cannot generate:**" line`);
    }
    // The flag-less default (legacy string generator) and the standalone drivers.
    for (const heading of ['(no mode flag)', 'metamorphic-fuzz.ts', 'canonical-java-gate.ts']) {
      const re = new RegExp('^###\\s+`' + heading.replace(/[().]/g, '\\$&') + '`[^\\n]*\\n([\\s\\S]*?)(?=^#{2,3}\\s)', 'm');
      const s = re.exec(README)?.[1];
      if (s === undefined) missing.push(`${heading}: no section`);
      else if (!/^\*\*Cannot generate:\*\*\s+\S/m.test(s)) missing.push(`${heading}: no "**Cannot generate:**" line`);
    }
    expect(missing).toEqual([]);
  });

  it('README mentions every CLI flag parseArgs accepts', () => {
    const flags = [...INDEX.matchAll(/case '(--[a-z-]+)':/g)].map((m) => m[1]!);
    expect(flags.length).toBeGreaterThan(10);
    const missing = flags.filter((f) => !README.includes('`' + f));
    expect(missing).toEqual([]);
  });

  it('README CI table lists every fuzz step in fuzzer-nightly.yml with the right placement', () => {
    const steps = workflowSteps(NIGHTLY).filter((s) => DRIVER_RE.test(s.body));
    expect(steps.length, 'no fuzz-driver steps parsed from the workflow').toBeGreaterThanOrEqual(15);
    const problems: string[] = [];
    for (const s of steps) {
      const row = README.split('\n').find((l) => l.startsWith('|') && l.includes(s.name));
      if (!row) {
        problems.push(`step "${s.name}" (job ${s.job}) has no row in the README CI table`);
        continue;
      }
      const cells = row.split('|').map((c) => c.trim());
      if (!cells.includes(s.placement)) {
        problems.push(`step "${s.name}": README row lacks placement cell "${s.placement}": ${row}`);
      }
      if (!cells.some((c) => c === '`' + s.job + '`')) {
        problems.push(`step "${s.name}": README row lacks job cell \`${s.job}\``);
      }
    }
    expect(problems).toEqual([]);
  });

  it('README CI table lists the ci.yml replay steps and the harness unit-guard step', () => {
    const replay = workflowSteps(CI).filter((s) => /fuzz-regressions\/replay\.ts/.test(s.body));
    expect(replay.length, 'no replay steps parsed from ci.yml').toBeGreaterThanOrEqual(2);
    const guard = workflowSteps(NIGHTLY).filter((s) => /conformance\/fuzzer\/__tests__/.test(s.body));
    expect(guard.length).toBeGreaterThanOrEqual(1);
    const problems: string[] = [];
    for (const s of [...replay, ...guard]) {
      if (!README.split('\n').some((l) => l.startsWith('|') && l.includes(s.name))) {
        problems.push(`step "${s.name}" has no row in the README CI table`);
      }
    }
    expect(problems).toEqual([]);
  });

  it('--anf section names exactly the ANF kinds the generator never draws', () => {
    const anfSrc = read('conformance/fuzzer/anf-differential.ts');
    const union = /type AnfValue =([\s\S]*?);\n/.exec(anfSrc)![1]!;
    const generated = [...union.matchAll(/kind: '(\w+)'/g)].map((m) => m[1]!);
    const allKinds = [...read('packages/runar-compiler/src/ir/anf-ir.ts').matchAll(/^\s+kind: '(\w+)';/gm)].map((m) => m[1]!);
    const notGenerated = allKinds.filter((k) => !generated.includes(k));
    expect(generated.length).toBeGreaterThan(5);
    expect(notGenerated).toEqual(expect.arrayContaining(['if', 'loop', 'add_output']));

    const s = section('--anf')!;
    expect(s, 'no --anf section').toBeDefined();
    const gen = /^\*\*Generates ANF kinds:\*\*\s+(.+)$/m.exec(s)?.[1];
    const not = /^\*\*Never generates ANF kinds:\*\*\s+(.+)$/m.exec(s)?.[1];
    expect(gen, 'no "Generates ANF kinds:" line').toBeDefined();
    expect(not, 'no "Never generates ANF kinds:" line').toBeDefined();
    const parse = (l: string) => [...l.matchAll(/`(\w+)`/g)].map((m) => m[1]!).sort();
    expect(parse(gen!)).toEqual([...generated].sort());
    expect(parse(not!)).toEqual([...notGenerated].sort());
  });

  it('the code facts the README relies on still hold', () => {
    // sourceLoc is stripped only when comparing ANF, never when comparing hex.
    const ir = read('conformance/fuzzer/ir-differential.ts');
    expect(ir).toMatch(/if \(k === 'sourceLoc'\) continue;/);
    expect(ir).toMatch(/compareHex \? output\.trim\(\)\.toLowerCase\(\) : canonicalizeJson\(output\)/);
    // --execute / --tri-modal / --spend-oracle are in-process: no tier subprocess.
    for (const f of ['execute-differential', 'tri-modal-differential', 'spend-oracle']) {
      expect(read(`conformance/fuzzer/${f}.ts`), `${f}.ts spawns processes`).not.toMatch(/child_process/);
    }
    // The native render strategy cannot express countdown / closed-bound loops.
    expect(ir).toMatch(/const wide = strategy === 'ts';/);
  });
});
