/**
 * F-175 — the "Emit verification step summary" step in ci.yml's
 * `runar-verification` job carries `if: always()` and printf's three of its
 * four table rows ('Parse + WF', 'ANF JSON round-trip',
 * 'pipelineConformance (modulo codegen axioms)') as the bare literal '56/56',
 * regardless of whether the gates that produce those numbers passed or
 * failed earlier in the same job. Only the fourth row (byte-exact) was
 * guarded, built from a real step output with a fallback for when the
 * binary never ran. 56 is also internally inconsistent with the rest of the
 * file (63 fixtures per one comment, 34/49 per another, 82 fixture
 * directories on disk) -- it was never derived from anything, it was typed.
 *
 * This test reads ci.yml as text (there is no YAML parser among the root
 * dependencies -- see tests/f053-strong-gates-run-on-push.test.ts, which
 * notes the same thing) and asserts:
 *   - the step's run script contains no bare 'N/N' (or similar undecorated
 *     literal) table-row value -- every row must be built from a shell
 *     variable, not typed into the YAML;
 *   - each of the four Check rows is parameterized (printf '%s' or
 *     equivalent), not a quoted literal;
 *   - the step's env: block pulls from at least three distinct earlier step
 *     ids' outputs (before the fix, only one — byte-exact-gate — existed),
 *     so each row is actually backed by a gate that ran earlier in the job,
 *     not just re-plumbing the one real value through more wires.
 *
 * What this proves: the step can no longer assert a fixed pass count that
 * does not depend on whether goldenLoad / roundtrip / pipelineConformance
 * actually succeeded. What it does not prove: that the step's arithmetic
 * (total minus deferred buckets) is correct, or that GitHub Actions
 * interprets $GITHUB_OUTPUT the way this test assumes -- GitHub Actions
 * cannot run here.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf-8');

/** Drop full-line comments so a literal mentioned in prose does not count. */
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

/** The lines of the named step within the `runar-verification` job. */
function stepLines(name: string): string[] {
  const lines = codeLines(read('.github/workflows/ci.yml'));
  const job = block(lines, /^ {2}runar-verification:\s*$/);
  expect(job, 'ci.yml: runar-verification job not found').toBeDefined();
  const idx = job!.findIndex((l) => new RegExp(`- name: ${name}$`).test(l.trim()));
  expect(idx, `ci.yml: step "${name}" not found in runar-verification`).toBeGreaterThanOrEqual(0);
  const rest = job!.slice(idx + 1);
  const end = rest.findIndex((l) => /^ {6}- /.test(l));
  return end < 0 ? rest : rest.slice(0, end);
}

/** The dedented body of a `key: |` multi-line scalar within `lines`. */
function scalarBlock(lines: string[], key: string): string {
  const b = block(lines, new RegExp(`^ {8}${key}: \\|\\s*$`));
  expect(b, `step has no "${key}: |" block`).toBeDefined();
  const pad = Math.min(...b!.map((l) => l.match(/^ */)![0].length));
  return b!.map((l) => l.slice(pad)).join('\n') + '\n';
}

describe('F-175: the verification summary never prints a hardcoded pass count', () => {
  const summary = () => stepLines('Emit verification step summary');

  it('the step exists and still runs unconditionally (if: always())', () => {
    const lines = summary();
    expect(lines.some((l) => /^ {8}if: always\(\)\s*$/.test(l))).toBe(true);
  });

  it('no table row is a bare "N/N" literal untouched by a shell variable', () => {
    const script = scalarBlock(summary(), 'run');
    // A printf line that forms a table row ("| label | value |\n") whose
    // value segment is a raw digit/digit pair with no '%s' and no '$' is
    // exactly the defect: a number typed into the YAML that is printed
    // whether or not the gates above it passed.
    const rowLines = script.split('\n').filter((l) => /printf\s+'\|.*\|.*\|/.test(l));
    expect(rowLines.length, 'expected at least the 4 Check rows plus header').toBeGreaterThanOrEqual(4);
    const hardcoded = rowLines.filter((l) => /\|\s*[0-9]+\/[0-9]+\s*\|/.test(l) && !/%s/.test(l));
    expect(hardcoded, `hardcoded pass-count row(s): ${JSON.stringify(hardcoded)}`).toEqual([]);
    // The specific literal the finding named, belt and suspenders.
    expect(script).not.toMatch(/56\/56/);
  });

  it('every Check row is parameterized from a shell variable, not a quoted literal', () => {
    const script = scalarBlock(summary(), 'run');
    for (const label of [
      'Parse \\+ WF',
      'ANF JSON round-trip',
      'Byte-exact vs\\. TS reference',
      'pipelineConformance \\(modulo codegen axioms\\)',
    ]) {
      const re = new RegExp(`printf '\\|\\s*${label}\\s*\\|[^']*'[^\\n]*`, 'm');
      const m = re.exec(script);
      expect(m, `no printf found for row "${label}"`).not.toBeNull();
      // Every occurrence of the row (success-path and any fallback) must be
      // parameterized or must be a documented non-numeric fallback like
      // "(did not run)" / "(binary did not run)" — never a bare count.
      const occurrences = script
        .split('\n')
        .filter((l) => new RegExp(`\\|\\s*${label}\\s*\\|`).test(l));
      expect(occurrences.length, `row "${label}" never printed`).toBeGreaterThan(0);
      for (const line of occurrences) {
        const isParameterized = /%s/.test(line);
        const isFallback = /\(.*did not run.*\)/.test(line);
        expect(
          isParameterized || isFallback,
          `row "${label}" prints a bare literal, not a step-derived value: ${line}`,
        ).toBe(true);
      }
    }
  });

  it('the step draws on at least three distinct earlier steps\' outputs', () => {
    const lines = summary();
    const env = block(lines, /^ {8}env:\s*$/) ?? [];
    const text = env.join('\n');
    const ids = new Set(
      [...text.matchAll(/steps\.([a-zA-Z0-9_-]+)\.outputs\.[a-zA-Z0-9_-]+/g)].map((m) => m[1]),
    );
    expect(
      [...ids],
      'only one gate (byte-exact-gate) fed the summary; the other three rows ' +
        'must be backed by their own gates too',
    ).not.toEqual(['byte-exact-gate']);
    expect(ids.size, `step ids feeding the summary: ${[...ids].join(', ')}`).toBeGreaterThanOrEqual(3);
  });
});
