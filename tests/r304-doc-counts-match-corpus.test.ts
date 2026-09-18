/**
 * Every number a document asserts about the checked-in tree must be recomputed
 * from that tree, not asserted.
 *
 * `conformance/fixture-count-doc.test.ts` (R-252) settled exactly one such
 * sentence — the fixture count in `conformance/README.md` — by re-running the
 * command that README itself names. Its regex is anchored to that one file, so
 * the identical defect survived three feet away in the root `README.md`, which
 * still claimed "64 fixtures" while the suite held 78. A guard scoped to one
 * file is how the thing it was written to catch gets caught again somewhere
 * else, so this one is scoped to the claim, not to the file: every place a
 * count appears, against one measurement function.
 *
 * The same class showed up in `packages/runar-ir-schema/src/input-limits.ts`,
 * where the DoS-bound justifications cited "227 checked-in conformance
 * artifacts" — and note which copy was wrong. That paragraph is duplicated in
 * all seven SDK envelope implementations, and all seven said 157, which is
 * correct. The single canonical original had rotted while its seven duplicates
 * held. The intuition runs the other way, which is exactly why the number
 * wants to be computed rather than asserted on either side.
 *
 * Adding a fixture, an artifact, or an integration test reddens the row whose
 * prose went stale, and names the file.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const conformanceTests = join(repoRoot, 'conformance', 'tests');

// ---------------------------------------------------------------------------
// Measurements — each one is the command a reader would run to settle a claim.
// ---------------------------------------------------------------------------

/** `find conformance/tests -name source.json | wc -l` */
function fixtureDirs(): string[] {
  return readdirSync(conformanceTests).filter((d) =>
    existsSync(join(conformanceTests, d, 'source.json')),
  );
}

/** Fixtures that opt out of full seven-tier Stack-IR / hex parity. */
function allowlistedFixtures(): string[] {
  return fixtureDirs().filter((d) => {
    const src = JSON.parse(
      readFileSync(join(conformanceTests, d, 'source.json'), 'utf8'),
    ) as { compilers?: unknown };
    return Array.isArray(src.compilers);
  });
}

/** `git ls-files 'conformance/tests/*' | grep -c '\.json$'` — the artifact
 *  corpus the wire-nesting bound is calibrated against. */
function conformanceJsonArtifacts(): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const p = join(dir, entry);
      if (statSync(p).isDirectory()) walk(p);
      else if (entry.endsWith('.json')) out.push(p);
    }
  };
  walk(conformanceTests);
  return out;
}

/** `find conformance/sdk-output/tests -name input.json | wc -l` */
function sdkOutputFixtures(): string[] {
  const dir = join(repoRoot, 'conformance', 'sdk-output', 'tests');
  return readdirSync(dir).filter((d) => existsSync(join(dir, d, 'input.json')));
}

/** Analyzer-conformance fixture directories. */
function analyzerFixtures(): string[] {
  const dir = join(repoRoot, 'conformance', 'analyzer');
  return readdirSync(dir).filter(
    (d) => statSync(join(dir, d)).isDirectory() && !d.startsWith('__') && d !== 'scripts',
  );
}

/**
 * `#[test]` functions under `integration/rust/tests/`, split by whether the
 * attribute block carries `#[cfg_attr(not(feature = "regtest"), ignore)]`.
 *
 * Counted by walking the contiguous run of `#[...]` attribute lines that the
 * `#[test]` belongs to, in both directions — the gate sits after `#[test]` in
 * this tree today, but a window heuristic that only looked backwards silently
 * reported 6 gated instead of 135.
 */
function rustIntegrationTests(): { total: number; gated: number; deflt: number } {
  const dir = join(repoRoot, 'integration', 'rust', 'tests');
  const files: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d)) {
      const p = join(d, e);
      if (statSync(p).isDirectory()) walk(p);
      else if (e.endsWith('.rs')) files.push(p);
    }
  };
  walk(dir);

  const GATE = 'cfg_attr(not(feature = "regtest"), ignore)';
  let total = 0;
  let gated = 0;
  for (const f of files) {
    const lines = readFileSync(f, 'utf8').split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i]!.trim() !== '#[test]') continue;
      total++;
      let lo = i;
      while (lo > 0 && lines[lo - 1]!.trim().startsWith('#[')) lo--;
      let hi = i;
      while (hi + 1 < lines.length && lines[hi + 1]!.trim().startsWith('#[')) hi++;
      if (lines.slice(lo, hi + 1).some((l) => l.includes(GATE))) gated++;
    }
  }
  return { total, gated, deflt: total - gated };
}

const MEASURE: Record<string, () => number> = {
  'conformance fixtures': () => fixtureDirs().length,
  'fixtures with a compilers allowlist': () => allowlistedFixtures().length,
  'fixtures without a compilers allowlist': () =>
    fixtureDirs().length - allowlistedFixtures().length,
  'conformance JSON artifacts': () => conformanceJsonArtifacts().length,
  'sdk-output fixtures': () => sdkOutputFixtures().length,
  'analyzer fixtures': () => analyzerFixtures().length,
  'rust integration tests (total)': () => rustIntegrationTests().total,
  'rust integration tests (regtest-gated)': () => rustIntegrationTests().gated,
  'rust integration tests (default)': () => rustIntegrationTests().deflt,
};

// ---------------------------------------------------------------------------
// Claims — (file, regex with one numeric capture group, measurement name).
// ---------------------------------------------------------------------------

interface Claim {
  file: string;
  measure: keyof typeof MEASURE;
  pattern: RegExp;
}

const CLAIMS: Claim[] = [
  // --- conformance fixture count -----------------------------------------
  {
    file: 'README.md',
    measure: 'conformance fixtures',
    pattern: /conformance suite in `conformance\/` contains (\d+) fixtures/,
  },
  {
    file: 'conformance/README.md',
    measure: 'conformance fixtures',
    pattern: /suite currently contains \*\*(\d+) fixtures\*\* under `tests\/`/,
  },
  {
    file: 'README.md',
    measure: 'fixtures with a compilers allowlist',
    pattern: /the (\d+) conformance fixtures that use them carry an explicit/,
  },
  {
    file: 'README.md',
    measure: 'fixtures without a compilers allowlist',
    pattern: /The other (\d+) are byte-identical across all seven/,
  },

  // --- SDK-output conformance --------------------------------------------
  {
    file: 'conformance/README.md',
    measure: 'sdk-output fixtures',
    pattern: /### SDK-output conformance \((\d+) fixtures, 7 SDKs\)/,
  },
  {
    file: 'conformance/README.md',
    measure: 'sdk-output fixtures',
    pattern: /`sdk-output\/tests\/` contains (\d+) fixtures/,
  },

  // --- analyzer conformance ----------------------------------------------
  // The same sdk-output count, duplicated into three SDK READMEs. All three
  // said 27 against a real 70 — a count is not safer for being repeated.
  {
    file: 'packages/runar-go/README.md',
    measure: 'sdk-output fixtures',
    pattern: /test case is one of (\d+) fixtures/,
  },
  {
    file: 'packages/runar-rs/README.md',
    measure: 'sdk-output fixtures',
    pattern: /contract is one of the (\d+) fixtures/,
  },
  {
    file: 'packages/runar-sdk/README.md',
    measure: 'sdk-output fixtures',
    pattern: /(\d+) fixtures pass on all seven SDKs/,
  },

  {
    file: 'conformance/analyzer/README.md',
    measure: 'analyzer fixtures',
    pattern: /Current state — (\d+) fixtures × 7 tiers/,
  },

  // --- wire-nesting calibration corpus (one original + seven duplicates) ---
  ...[
    'packages/runar-ir-schema/src/input-limits.ts',
    'packages/runar-sdk/src/envelope.ts',
    'packages/runar-go/sdk_envelope.go',
    'packages/runar-rs/src/sdk/envelope.rs',
    'packages/runar-py/runar/sdk/envelope.py',
    'packages/runar-zig/src/sdk_envelope.zig',
    'packages/runar-rb/lib/runar/sdk/envelope.rb',
    'packages/runar-java/src/main/java/runar/lang/sdk/Envelope.java',
  ].map((file): Claim => ({
    file,
    measure: 'conformance JSON artifacts',
    pattern: /the deepest of the (\d+) checked-in conformance artifacts/,
  })),

  // --- rust integration tests ---------------------------------------------
  {
    file: 'integration/rust/README.md',
    measure: 'rust integration tests (total)',
    pattern: /This runs all (\d+) tests/,
  },
  {
    file: 'integration/rust/README.md',
    measure: 'rust integration tests (default)',
    pattern: /### 1\. Default \(offline\) — (\d+) tests/,
  },
  {
    file: 'integration/rust/README.md',
    measure: 'rust integration tests (regtest-gated)',
    pattern: /### 2\. Opt-in \(on-chain\) — (\d+) tests gated by `regtest` feature/,
  },
];

/**
 * Strip per-language comment leaders and collapse whitespace, so one regex
 * matches the same sentence whether it is wrapped behind ` * `, `// `, `/// `,
 * `#: `, `# ` or nothing at all.
 *
 * Markdown is left alone apart from the whitespace collapse: `#` there opens a
 * heading, and several of the claims below live in one.
 */
function flatten(text: string, isMarkdown: boolean): string {
  const lines = text.split('\n');
  const stripped = isMarkdown
    ? lines
    : lines.map((l) => l.replace(/^\s*(\/\/\/|\/\/|#:|#|\*|--)\s?/, ''));
  return stripped.join(' ').replace(/\s+/g, ' ');
}

describe('R-304: counts in documents are recomputed from the tree, not asserted', () => {
  for (const claim of CLAIMS) {
    it(`${claim.file} — ${claim.measure}`, () => {
      const path = join(repoRoot, claim.file);
      expect(existsSync(path), `${claim.file} does not exist`).toBe(true);

      const m = flatten(readFileSync(path, 'utf8'), claim.file.endsWith('.md')).match(
        claim.pattern,
      );
      expect(
        m,
        `the sentence stating "${claim.measure}" has moved or changed shape in ${claim.file} ` +
          `— re-point the regex, do not delete the row`,
      ).not.toBeNull();

      const measured = MEASURE[claim.measure]!();
      expect(
        Number(m![1]),
        `${claim.file} claims ${m![1]} for "${claim.measure}"; the tree measures ${measured}`,
      ).toBe(measured);
    });
  }

  it('anti-vacuity: every measurement is non-trivial and they are not the same number', () => {
    // A measurement function that silently returned 0, or two that collapsed
    // onto one value, would make most rows above pass by accident.
    const values = Object.entries(MEASURE).map(([k, f]) => [k, f()] as const);
    for (const [name, v] of values) {
      expect(v, `measurement "${name}" returned a degenerate value`).toBeGreaterThan(0);
    }
    // Every claim would also pass if the measurements had all collapsed onto
    // one number, so require them to stay distinguishable.
    expect(new Set(values.map(([, v]) => v)).size).toBeGreaterThan(5);
    expect(conformanceJsonArtifacts().length).toBeGreaterThan(fixtureDirs().length);
    expect(rustIntegrationTests().total).toBe(
      rustIntegrationTests().gated + rustIntegrationTests().deflt,
    );
  });
});

describe('R-304: the primitive families README names all have fixtures', () => {
  // The same sentence that miscounted the suite also advertised
  // "BabyBear / KoalaBear / Merkle / FRI primitives". Two of those four have no
  // fixture at all (`ls conformance/tests | grep -ci koala` → 0, `grep -ci fri`
  // → 0) — the prose listed the roadmap, not the corpus.
  it('every primitive family named in the fixture sentence matches a fixture directory', () => {
    const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8');
    const sentence = readme.match(
      /conformance suite in `conformance\/` contains \d+ fixtures spanning ([^.]+)\./,
    );
    expect(sentence, 'the fixture-span sentence has moved or changed shape').not.toBeNull();

    // Capitalised, ≥3-character items are the primitive families; the
    // lowercase items in the same list ("escrow", "stateful counters") name
    // contract shapes and are checked by the fixture count itself.
    // `NIST` is a standards-body qualifier and `primitives` a generic tail;
    // neither ever appears in a directory name.
    const families = sentence![1]!
      .split(/,|\band\b/)
      .flatMap((s) => s.split('/'))
      .map((s) => s.trim().replace(/^NIST\s+/, '').replace(/\s+primitives$/, '').trim())
      .filter((s) => /^[A-Z][A-Za-z0-9+\- ]*$/.test(s) && s.length > 2);
    expect(families.length, 'no family names extracted (anti-vacuity)').toBeGreaterThan(3);

    const dirs = fixtureDirs().map((d) => d.toLowerCase().replace(/[^a-z0-9]/g, ''));
    const orphans = families.filter((f) => {
      const key = f.toLowerCase().replace(/[^a-z0-9]/g, '');
      return !dirs.some((d) => d.includes(key));
    });
    expect(
      orphans,
      `README names primitive families with no conformance fixture: ${orphans.join(', ')}`,
    ).toEqual([]);
  });
});
